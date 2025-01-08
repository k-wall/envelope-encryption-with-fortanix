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
import com.fortanix.sdkms.v1.model.KeyObject;
import com.fortanix.sdkms.v1.model.ObjectType;
import com.fortanix.sdkms.v1.model.SobjectRequest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.UUID;

public class Ghosts {

    /**
     * Usage:  Main {apikey} {basepath}
     * @throws Exception
     */
    public static void main(String[] argv) throws Exception {

        String apiKey = argv[0];
        String basePath = argv[1];

        var client1 = createAutenticatedApiClient(apiKey, basePath);
        var client2 = createAutenticatedApiClient(apiKey, basePath);

        SecurityObjectsApi client1SoApi = new SecurityObjectsApi(client1.apiClient());
        SecurityObjectsApi client2SoApi = new SecurityObjectsApi(client2.apiClient());

        var keyRequest = new SobjectRequest()
                .name("mykey-" + UUID.randomUUID())
                .keySize(256)
                .objType(ObjectType.AES);
        var key = client1SoApi.generateSecurityObject(keyRequest);

        var readByClient1 = client1SoApi.getSecurityObject(key.getKid(), null, false, false);
        System.out.println("Key read by client1" + readByClient1);

        var readByClient2 = client2SoApi.getSecurityObject(key.getKid(), null, false, false);
        System.out.println("Key read by client2" + readByClient2);

        client1SoApi.deleteSecurityObject(key.getKid());
        System.out.println("Key deleted by client1" + readByClient1);


        try {
            var rereadByClient1 = client1SoApi.getSecurityObject(key.getKid(), null, false, false);
            System.out.println("Key reread by client1 " + rereadByClient1);
        } catch (ApiException e) {
            System.out.println("Client 1 failed to reread key (expected)");
        }

        //Thread.sleep(1000L);  If add a sleep here, the problem goes away.
        //It feels like the server side cache of session2 has somehow cached the existence of key1

        try {
            var rereadByClient2 = client2SoApi.getSecurityObject(key.getKid(), null, false, false);
            System.out.println("UNEXPECTED: Client 2 was able to read deleted key. " + rereadByClient2);
        } catch (ApiException e) {
            System.out.println("Client 2 failed to reread key (expected)");
        }

    }

    private static CloseableClient createAutenticatedApiClient(String apiKey, String basePath) throws ApiException {
        ApiClient apiClient = new ApiClient();
        //apiClient.setDebugging(true);
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

}
