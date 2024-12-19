import javax.crypto.SecretKey;

public record EncryptedDek(SecretKey dek, byte[] encryptedDek, byte[] encryptedDekIv) {
}
