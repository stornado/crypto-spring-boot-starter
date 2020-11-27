package com.zxytech.crypto.starter.annotation;

import com.zxytech.crypto.starter.advice.DecryptRequestBodyAdvice;
import com.zxytech.crypto.starter.advice.EncryptResponseBodyAdvice;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.context.annotation.Import;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@Import({
    EncryptResponseBodyAdvice.class,
    DecryptRequestBodyAdvice.class
})
public @interface EnableSecurity {

}
