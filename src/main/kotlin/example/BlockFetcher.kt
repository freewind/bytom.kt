package example

import `in`.freewind.bytom.go_exports.GoBytom
import org.apache.commons.io.IOUtils
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*
import kotlin.experimental.xor

val goBytom = GoBytom.load()!!

fun generateEd25519Keys(): Pair<ByteArray, ByteArray> {
    val privateKey = goBytom.ed25519GeneratePrivateKey()
    val publicKey = goBytom.ed25519PublicKey(privateKey)
    return privateKey to publicKey
}

fun generateCurve25519Keys(): Pair<ByteArray, ByteArray> {
    return goBytom.curve25519GenerateKeyPair().let {
        it.privateKey to it.publicKey
    }
}

fun sortKeys(key1: ByteArray, key2: ByteArray): Pair<ByteArray, ByteArray> {
    return key1.zip(key2).dropWhile { it.first == it.second }
            .firstOrNull()?.let {
                when (it.first.toPositiveInt() < it.second.toPositiveInt()) {
                    true -> key1 to key2
                    else -> key2 to key1
                }
            } ?: key1 to key2
}

fun main(args: Array<String>) {

    val (privateKey, publicKey) = generateEd25519Keys().apply {
        printBytes("privateKey", this.first)
        printBytes("publicKey", this.second)
    }

    val socket = Socket("127.0.0.1", 46666)

    val inputStream = socket.getInputStream()
    val outputStream = socket.getOutputStream()

    val (ephPrivateKey, ephPublicKey) = generateCurve25519Keys().apply {
        printBytes("ephPrivateKey", this.first)
        printBytes("ephPublicKey", this.second)
    }

    outputStream.run {
        printBytes("send public key", ephPublicKey)
        this.writeFlush(ephPublicKey)
    }

    val remoteEphPubKey = IOUtils.readFully(inputStream, 32).apply { printBytes("remoteEphPubKey", this) }

    val challenge = genChallenge(remoteEphPubKey, ephPublicKey).apply { printBytes("challenge", this) }

    val signature = goBytom.ed25519Sign(privateKey, challenge).apply { printBytes("signature", this) }

    val authMessage = goBytom.wire_AuthSigMessage(publicKey, signature).apply { printBytes("authMessage", this) }

    val (remotePublicKey, remoteSignature) = SecretConnection(inputStream, outputStream, ephPrivateKey, ephPublicKey, remoteEphPubKey).run {
        println("Send AuthMessage to peer")
        this.sendSecret(authMessage)
        this.readSecret(example.AUTH_SIGNATURE_MESSAGE_SIZE)
    }.apply {
        printBytes("remotePublicKey", this.first)
        printBytes("remoteSignature", this.second)
    }

    if (goBytom.ed25519VerifySignature(remotePublicKey, challenge, remoteSignature)) {
        println("Verified!")
    } else {
        println("Failed!")
    }
}

class SecretConnection(private val input: InputStream, private val outputStream: OutputStream, private val ephPrivateKey: ByteArray, private val ephPublicKey: ByteArray, private val remoteEphPubKey: ByteArray) {

    private val sharedKey = goBytom.curve25519PreComputeSharedKey(remoteEphPubKey, ephPrivateKey).apply {
        printBytes("sharedKey", this)
    }

    private val nonces = genNonces()
    private var receivedNonce = nonces.first.apply {
        printBytes("receivedNonce", this)
    }
    private var sendNonce = nonces.second.apply {
        printBytes("sendNonce", this)
    }

    fun sendSecret(data: ByteArray) {
        IntRange(0, data.size - 1).step(DATA_MAX_SIZE).forEach { start ->
            val length = Math.min(DATA_MAX_SIZE, data.size - start)
            println("length of current frame data: " + length)
            val buffer = ByteBuffer.allocate(TOTAL_FRAME_SIZE).let {
                it.order(ByteOrder.BIG_ENDIAN)
                it.putShort(length.toShort())
                it.put(data, start, length)
            }

            val sealedBytes = goBytom.secretboxSeal(buffer.array(), sendNonce, sharedKey)
            require(sealedBytes.size == SEALED_FRAME_SIZE)

            increase2(sendNonce)
            printBytes("write sealedBytes", sealedBytes)
            outputStream.writeFlush(sealedBytes)
        }
    }

    private fun genNonces(): Pair<ByteArray, ByteArray> {
        val (lowPubKey, highPubKey) = sortKeys(ephPublicKey, remoteEphPubKey)
        printBytes("lowPubKey", lowPubKey)
        printBytes("highPubKey", highPubKey)

        val nonce1 = hash24(lowPubKey + highPubKey)
        val nonce2 = Arrays.copyOf(nonce1, nonce1.size).apply {
            this[size - 1] = this[size - 1] xor 1
        }

        val (receiveNonce, sendNonce) = when (lowPubKey) {
            ephPublicKey -> nonce1 to nonce2
            else -> nonce2 to nonce1
        }

        return receiveNonce to sendNonce
    }

    private fun increase2(nonce: ByteArray) {
        increase1(nonce)
        increase1(nonce)
    }

    private fun increase1(nonce: ByteArray) {
        IntRange(0, nonce.size - 1).reversed().forEach { i ->
            nonce[i] = nonce[i].inc()
            if (nonce[i] != 0.toByte()) {
                return
            }
        }
    }

    fun readSecret(dataSize: Int): Pair<ByteArray, ByteArray> {
        var readCount = 0
        val buffer = ByteArrayOutputStream(dataSize)
        while (readCount < dataSize) {
            val sealedFrame = IOUtils.readFully(input, SEALED_FRAME_SIZE).apply {
                printBytes("read sealedFrame", this)
            }

            val frame = goBytom.secretboxOpen(sealedFrame, receivedNonce, sharedKey).apply {
                printBytes("read frame", this)
            }

            val message = ByteBuffer.wrap(frame).let {
                it.order(ByteOrder.BIG_ENDIAN)
                val dataLength = it.short
                it.readBytes(dataLength.toInt())
            }.apply {
                printBytes("read message", this)
            }

            increase2(receivedNonce)
            buffer.write(message)
            readCount += message.size
        }
        val x = buffer.toByteArray()
        printBytes("read x", x)

        return goBytom.unwire_AuthSigMessage(x).let {
            it.publicKey to it.signature
        }
    }

}

private fun ByteBuffer.readBytes(length: Int): ByteArray {
    val array = ByteArray(length)
    this.get(array)
    return array
}

val DATA_LEN_SIZE = 2
val DATA_MAX_SIZE = 1024
val TOTAL_FRAME_SIZE = DATA_MAX_SIZE + DATA_LEN_SIZE
val SECRETBOX_OVERHEAD = 16 // go: secretebox.Overhead = poly1305.TagSize = 16
val SEALED_FRAME_SIZE = TOTAL_FRAME_SIZE + SECRETBOX_OVERHEAD
val AUTH_SIGNATURE_MESSAGE_SIZE = (32 + 1) + (64 + 1)

fun genChallenge(key1: ByteArray, key2: ByteArray): ByteArray {
    val (lowPubKey, highPubKey) = sortKeys(key1, key2)
    printBytes("lowPubKey", lowPubKey)
    printBytes("highPubKey", highPubKey)

    return hash32(lowPubKey + highPubKey)
}

fun hash24(input: ByteArray): ByteArray {
    // hash is only 20 bytes
    val hash = goBytom.ripemd160Hash(input)
    val hash24 = hash + ByteArray(4)
    require(hash24.size == 24)
    return hash24
}

fun hash32(input: ByteArray): ByteArray {
    val hash = goBytom.sha256Hash(input)
    require(hash.size == 32)
    return hash
}

fun printBytes(name: String, array: ByteArray?) {
    if (array == null) {
        print("$name: null")
    } else {
        print("$name: len(${array.size}) ")
        println(array.map { it.toHex() }.joinToString(separator = " "))
    }
}

fun Byte.toPositiveInt() = toInt() and 0xFF

fun Byte.toHex() = toPositiveInt().toString(16).padStart(2, '0')

fun OutputStream.writeFlush(data: ByteArray) {
    this.write(data)
    this.flush()
}