import com.fortanix.sdkms.v1.ApiClient;
import com.fortanix.sdkms.v1.ApiException;
import com.fortanix.sdkms.v1.Configuration;
import com.fortanix.sdkms.v1.api.AuthenticationApi;
import com.fortanix.sdkms.v1.api.EncryptionAndDecryptionApi;
import com.fortanix.sdkms.v1.api.SecurityObjectsApi;
import com.fortanix.sdkms.v1.auth.ApiKeyAuth;
import com.fortanix.sdkms.v1.model.AuthResponse;
import com.fortanix.sdkms.v1.model.CryptMode;
import com.fortanix.sdkms.v1.model.DecryptRequest;
import com.fortanix.sdkms.v1.model.DecryptResponse;
import com.fortanix.sdkms.v1.model.EncryptRequest;
import com.fortanix.sdkms.v1.model.EncryptResponse;
import com.fortanix.sdkms.v1.model.KeyObject;
import com.fortanix.sdkms.v1.model.KeyOperations;
import com.fortanix.sdkms.v1.model.ObjectType;
import com.fortanix.sdkms.v1.model.SobjectDescriptor;
import com.fortanix.sdkms.v1.model.SobjectRequest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.UUID;

public class EnvelopeEncryptionWithFortanix {

    /**
     * Usage:  Main {apikey} {basepath}
     * @throws Exception
     */
    public static void main(String[] argv) throws Exception {

        String apiKey = argv[0];
        String basePath = argv[1];

        var client = createAutenticatedApiClient(apiKey, basePath);

        SecurityObjectsApi securityObjectsApi = new SecurityObjectsApi(client.apiClient());
        EncryptionAndDecryptionApi encryptionAndDecryptionApi = new EncryptionAndDecryptionApi(client.apiClient());

        var kek = createKek(securityObjectsApi);

        // Create DEK
        var dek = createDek(securityObjectsApi, encryptionAndDecryptionApi, kek);

        // use dek.secretKey() to encrypt some data -> cipherText
        // blob = kek id + dek.encryptedDek + dek.encryptedDekIv + cipherText
        // store blob

        client.close();

        // later...  retrieve blob
        // unpack kek id, dek.encryptedDek, dek.encryptedDekIv, cipherText

        var client2 = createAutenticatedApiClient(apiKey, basePath);

        var secretKey = unwrapDek(new EncryptionAndDecryptionApi(client2.apiClient()), kek, dek.encryptedDek(), dek.encryptedDekIv());

        System.out.println("Key material equal : " + Arrays.equals(secretKey.getEncoded(), dek.dek().getEncoded()));
        // use secretKey to decrypt cipherText -> plaintext
    }

    private static CloseableClient createAutenticatedApiClient(String apiKey, String basePath) throws ApiException {
        ApiClient apiClient = new ApiClient();
        apiClient.setDebugging(true);
        apiClient.setBasicAuthString(apiKey);
        apiClient.setBasePath(basePath);

        Configuration.setDefaultApiClient(apiClient);


        AuthenticationApi authApi = new AuthenticationApi(apiClient);
        AuthResponse response = authApi.authorize();

        ApiKeyAuth auth = (ApiKeyAuth) apiClient.getAuthentication("bearerToken");
        auth.setApiKey(response.getAccessToken());
        auth.setApiKeyPrefix("Bearer");
        return new CloseableClient(apiClient, authApi);
    }

    private static SecretKey unwrapDek(EncryptionAndDecryptionApi encryptionAndDecryptionApi, KeyObject kek, byte[] encryptedDek, byte[] encryptedDekIv) throws ApiException {

        // unwrap the DEK's ciphered key material using the KEK
        DecryptRequest decryptRequest = new DecryptRequest();
        decryptRequest
                .alg(ObjectType.AES)
                .cipher(encryptedDek)
                .mode(CryptMode.CBC)
                .iv(encryptedDekIv);

        DecryptResponse decryptResponse = encryptionAndDecryptionApi.decrypt(kek.getKid(), decryptRequest);

        return new SecretKeySpec(decryptResponse.getPlain(),  "AES");
    }

    private static EncryptedDek createDek(SecurityObjectsApi securityObjectsApi, EncryptionAndDecryptionApi encryptionAndDecryptionApi, KeyObject kek) throws Exception {
        KeyObject exportedDekKey = createDekKey(securityObjectsApi);

        // wrap the DEK's key material using the KEK
        // Faisal: I found you can't use wrapkey with a transient key.  https://support.fortanix.com/apidocs/wrap-a-security-object-with-another-security-object
        var dekKeyMaterial = exportedDekKey.getValue();
        EncryptRequest encryptRequest = new EncryptRequest();
        encryptRequest
                .alg(ObjectType.AES)
                .plain(dekKeyMaterial)
                .mode(CryptMode.CBC);
        EncryptResponse encryptResponse = encryptionAndDecryptionApi.encrypt(kek.getKid(), encryptRequest);
        byte[] encryptedDek = encryptResponse.getCipher();
        byte[] encryptedDekIv = encryptResponse.getIv();

        SecretKey dek = new SecretKeySpec(exportedDekKey.getValue(),  "AES");
        return new EncryptedDek(dek, encryptedDek, encryptedDekIv);
    }

    private static KeyObject createDekKey(SecurityObjectsApi securityObjectsApi) throws ApiException {
        // create transient key to be the DEK
        KeyObject dekKey = createTransientExportabkeKeyObject(securityObjectsApi);
        // Faisal: Is it possible to have the transient key's key material returned in the response?
        // I'd prefer to avoid the export API if I can.

        // Need to export the transient key to get the live key material
        SobjectDescriptor soDescriptor = new SobjectDescriptor().transientKey(dekKey.getTransientKey());
        var exported = securityObjectsApi.getSecurityObjectValueEx(soDescriptor);
        // Faisal: once the I've exported the key material, I don't need the transient key to remain in the server's session.
        // I don't think https://support.fortanix.com/docs/deleting-a-security-object works for transient keys.   Is there some other
        // way to get the server to forget the key.   The session used by the application might be long-lived.  I am concerned that 
        // transient key resources might exhaust the server side.
        return export;
    }

    private static KeyObject createTransientExportabkeKeyObject(SecurityObjectsApi securityObjectsApi1) throws ApiException {
        var dekKeyRequest = new SobjectRequest()
                ._transient(true)
                .name("myDEK")
                .keySize(256)
                .objType(ObjectType.AES)
                .addKeyOpsItem(KeyOperations.EXPORT);
        return securityObjectsApi1.generateSecurityObject(dekKeyRequest);
    }

    private static KeyObject createKek(SecurityObjectsApi securityObjectsApi) throws ApiException {
        var kekKeyRequest = new SobjectRequest()
                .name("myKEK-" + UUID.randomUUID())
                .keySize(256)
                .objType(ObjectType.AES);
        return securityObjectsApi.generateSecurityObject(kekKeyRequest);
    }
}
