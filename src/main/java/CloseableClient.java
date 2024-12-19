import com.fortanix.sdkms.v1.ApiClient;

public record CloseableClient(ApiClient apiClient, com.fortanix.sdkms.v1.api.AuthenticationApi auth) implements AutoCloseable {
    @Override
    public void close() throws Exception {
        auth.terminate();
    }
}
