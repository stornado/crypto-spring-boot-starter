package com.zxytech.crypto.starter.annotation;

import java.lang.reflect.Method;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;

@Slf4j
public class CryptoDetector {

    //根据类或者方法上面是否有@EncryptResponse注解进行是否加密操作
    public static boolean encryptEnabled(MethodParameter mp) {
        if (log.isDebugEnabled()) {
            log.debug("Encrypt Enabled Detector for {}", mp.getMethod());
        }
        boolean encrypt = false;
        boolean classPresentAnno = mp.getContainingClass()
            .isAnnotationPresent(EncryptResponse.class);
        if (classPresentAnno) {
            encrypt = mp.getContainingClass().getAnnotation(EncryptResponse.class).enable();
            if (!encrypt) {
                return false;
            }
        }
        Method m = mp.getMethod();
        boolean methodPresentAnno =
            m != null && m.isAnnotationPresent(EncryptResponse.class);
        if (methodPresentAnno) {
            encrypt = m.getAnnotation(EncryptResponse.class).value();
        }
        return encrypt;
    }

    //根据类或者方法上面是否有@DecryptRequest注解进行是否解密操作
    public static boolean decryptEnabled(MethodParameter mp) {
        if (log.isDebugEnabled()) {
            log.debug("Decrypt Enabled Detector for {}", mp.getMethod());
        }
        boolean decrypt = false;
        boolean classPresentAnno = mp.getContainingClass()
            .isAnnotationPresent(DecryptRequest.class);
        if (classPresentAnno) {
            decrypt = mp.getContainingClass().getAnnotation(DecryptRequest.class).enable();
            if (!decrypt) {
                return false;
            }
        }
        Method m = mp.getMethod();
        boolean methodPresentAnno =
            m != null && m.isAnnotationPresent(DecryptRequest.class);
        if (methodPresentAnno) {
            decrypt = m.getAnnotation(DecryptRequest.class).value();
        }
        return decrypt;
    }

}
