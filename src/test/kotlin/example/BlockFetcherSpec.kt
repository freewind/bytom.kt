package example

import org.apache.commons.codec.binary.Hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class BlockFetcherSpec {

    @Test
    fun `sortKeys should return keys in correct order`() {
        val key1 = Hex.decodeHex("43 e0 b2 a2 90 a3 66 bc d3 b4 94 6a 8f 06 f4 80 55 d9 ce 52 ad 03 9e 81 a9 a5 80 b8 3b 61 f8 18".replace(" ", ""))
        val key2 = Hex.decodeHex("f5 88 0a 31 3a 83 a2 92 01 c5 63 69 8e ab 19 b9 4d 82 25 4c 19 59 81 04 05 7c df 35 91 08 b9 33".replace(" ", ""))
        val challenge = genChallenge(key1, key2)
        printBytes("challenge", challenge)
    }

    @Test
    fun `sortKeys`() {
        val key1 = Hex.decodeHex("f5 88 0a 31 3a 83 a2 92 01 c5 63 69 8e ab 19 b9 4d 82 25 4c 19 59 81 04 05 7c df 35 91 08 b9 33".replace(" ", ""))
        val key2 = Hex.decodeHex("43 e0 b2 a2 90 a3 66 bc d3 b4 94 6a 8f 06 f4 80 55 d9 ce 52 ad 03 9e 81 a9 a5 80 b8 3b 61 f8 18".replace(" ", ""))
        val (low, high) = sortKeys(key1, key2)
        assertThat(low).isSameAs(key2)
        assertThat(high).isSameAs(key1)
    }

}