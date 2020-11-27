package com.zxytech.crypto.starter.config;

import com.zxytech.crypto.starter.crypt.AlgorithmType;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "crypto")
public class CryptoProperties {

    private final Decrypt decrypt = new Decrypt();
    private final Encrypt encrypt = new Encrypt();
    private final Algorithm algorithm = new Algorithm();
    private String charset;

    @Data
    public static class Decrypt {

        private Boolean enable;
    }

    @Data
    public static class Encrypt {

        private Boolean enable;
    }

    @Data
    public static class Algorithm {

        private AlgorithmType use;
    }
}
