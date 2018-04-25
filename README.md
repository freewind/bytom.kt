Kotlin Implementation of Bytom
==============================

When reading the code of [bytom](https://github.com/Bytom/bytom), I try to use Kotlin to implement the same functions of it.

My goal of this project:
1. Learn Go better
2. Learn Kotlin better
3. Learn Bytom better

Please note since there are several crypto related Go functions used in Bytom which are hard(or impossible) to find exactly same implementation in Java world, 
I have to create another project to export some of them to Java, and use them in Kotlin: <https://github.com/freewind/bytom-exports-go-functions>.
Without it, it's almost impossible to interact with Bytom's node with correct data bytes.

Progress:
- [x] Create connection with real Bytom's node, and are able to create secret connection
- [ ] Get blocks

Setup
-----

1. Setup [bytom-exports-go-functions](https://github.com/freewind/bytom-exports-go-functions) first, follow the README there
2. Setup this project:

```
brew install go
export GOPATH=$(go env GOPATH)
export GOROOT=$(go env GOROOT)
```

```
./gradlew compile
```

Since it's in very early development, it's better for you to run the classes in IDE directly.