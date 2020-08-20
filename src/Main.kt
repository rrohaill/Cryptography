fun main(args: Array<String>) {

    val secretKey: String =
        "662ede816988e58fb6d057d9d85605e0"

    var encryptor = AESEncryptorGCM()

    val encryptedValue: String? =encryptor.encrypt("Rohail", secretKey)
    println(encryptedValue)

    val decryptedValue: String? =encryptor.decryptWithAES(secretKey, encryptedValue)
    println(decryptedValue)
}