package com.zxytech.crypto.starter.config;

import com.zxytech.crypto.starter.config.CryptoProperties.Algorithm;
import com.zxytech.crypto.starter.crypt.AlgorithmType;
import com.zxytech.crypto.starter.crypt.Crypto;
import com.zxytech.crypto.starter.crypt.impl.AESCrypto;
import com.zxytech.crypto.starter.crypt.impl.DES3Crypto;
import com.zxytech.crypto.starter.crypt.impl.RSACrypto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;


@Slf4j
@Configuration
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoAutoConfiguration {

    private static final String AES_KEYS_REQUIRED_MISSING = "properties [crypto.aes.seed] required";
    private static final String DES3_KEYS_REQUIRED_MISSING = "";
    private static final String RSA_KEYS_REQUIRED_MISSING = "";

    CryptoProperties cryptoProperties;

    @Value("${crypto.aes.seed:}")
    private String aesSeed;
    @Value("${crypto.desede.key:}")
    private String des3Key;

    @Autowired
    public CryptoAutoConfiguration(
        CryptoProperties cryptoProperties) {
        this.cryptoProperties = cryptoProperties;
    }


    @Bean("crypto")
    @ConditionalOnMissingBean
    public Crypto getCrypto(CryptoProperties cryptoProperties) {
        Algorithm algorithm = cryptoProperties.getAlgorithm();
        if (algorithm == null) {
            if (StringUtils.isEmpty(aesSeed)) {
                throw new MissingRequiredPropertiesException(
                    AES_KEYS_REQUIRED_MISSING);
            }
            return new AESCrypto(aesSeed);
        }
        AlgorithmType algorithmType = algorithm.getUse();
        if (algorithmType == null) {
            if (StringUtils.isEmpty(aesSeed)) {
                throw new MissingRequiredPropertiesException(
                    AES_KEYS_REQUIRED_MISSING);
            }
            return new AESCrypto(aesSeed);
        }
        switch (algorithmType) {
            case DES3:
                if (StringUtils.isEmpty(des3Key)) {
                    throw new MissingRequiredPropertiesException(DES3_KEYS_REQUIRED_MISSING);
                }
                return new DES3Crypto(des3Key);
            case RSA:
                return new RSACrypto();
            case AES:
            default:
                if (StringUtils.isEmpty(aesSeed)) {
                    throw new MissingRequiredPropertiesException(
                        AES_KEYS_REQUIRED_MISSING);
                }
                return new AESCrypto(aesSeed);
        }
    }
}

