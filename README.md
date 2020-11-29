# Crypto Spring Boot Starter

use spring advice to add request & response crypto support

## Example

https://github.com/stornado/crypto-spring-boot-starter/tree/example

```
.
├── pom.xml
└── src
    ├── main
    │   ├── java
    │   │   └── com.zxytech.example.crypto
    │   │       ├── CryptoStarterExampleApplication.java
    │   │       ├── controller
    │   │       │   ├── CryptoController.java
    │   │       │   └── HelloController.java
    │   │       └── domain
    │   │           └── User.java
    │   └── resources
    │       └── application.properties
    └── test
        └── resources
            ├── example.http
            └── http-client.env.json
```

### sample `application.properties`

```properties
# crypto config
crypto.encrypt.enable=true
crypto.decrypt.enable=true

# support AES
crypto.algorithm.use=AES

# AES
crypto.aes.seed=aescrypt
```

### OR: add `crypto` bean to custom crypto algorithm

```java
@Component
@Qualifier("crypto")
public class YourCrypto implements Crypto {

    @Override
    public byte[] decrypt(byte[] data) {
        // ... your implements
        return result;
    }

    @Override
    public byte[] encrypt(byte[] data) {
        // ... your implements
        return result;
    }
}

```

## License

[Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)