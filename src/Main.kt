fun main(args: Array<String>) {

    val SECRET_KEY: String =
        "662ede816988e58fb6d057d9d85605e0"

    var encryptor: AESEncryptor = AESEncryptor()

    val encryptedValue: String? =encryptor.encrypt("Rohail", SECRET_KEY)
    println(encryptedValue)

    val decryptedValue: String? =encryptor.decryptWithAES(SECRET_KEY, encryptedValue)
    println(decryptedValue)
}