package com.zxytech.crypto.starter.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zxytech.crypto.starter.annotation.CryptoDetector;
import com.zxytech.crypto.starter.crypt.Crypto;
import com.zxytech.crypto.starter.request.Request;
import com.zxytech.crypto.starter.request.RequestException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonInputMessage;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

@Slf4j
@ControllerAdvice
@ConditionalOnProperty(prefix = "crypto.decrypt", name = "enable", havingValue = "true", matchIfMissing = false)
public class DecryptRequestBodyAdvice extends RequestBodyAdviceAdapter {

    @Value("${crypto.request.timeout:15000}")
    private Long requestTimeout;

    @Value("${crypto.charset:UTF-8}")
    private String charset = "UTF-8";
    @Autowired
    private Crypto crypto;

    private static Request validateRequestThenGetRequest(HttpInputMessage inputMessage,
        String charset, long requestTimeout)
        throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        String requestBody = IOUtils.toString(inputMessage.getBody(), charset);
        Request request = mapper.readValue(requestBody, Request.class);
        if (request == null || request.getEncrypt() == null) {
            throw new RequestException("Request{encrypt,ts,nc,sign} Required!");
        }
        long now = System.currentTimeMillis();
        if (request.getTimestamp() > now + requestTimeout
            || request.getTimestamp() < now - requestTimeout) {
            throw new RequestException("Request timeout! invalid ts");
        }
        if (!DigestUtils.md5DigestAsHex(String
            .format("ts=%d&nc=%s&encrypt=%s",
                request.getTimestamp(), request.getNonce(), request.getEncrypt()).getBytes())
            .equalsIgnoreCase(request.getSign())) {
            throw new RequestException("Request Sign Err! invalid sign");
        }

        return request;
    }

    @Override
    public boolean supports(MethodParameter mp, Type targetType,
        Class<? extends HttpMessageConverter<?>> converter) {
        if (log.isDebugEnabled()) {
            log.debug("Request Target: {}", targetType);
        }
        return CryptoDetector.decryptEnabled(mp);
    }

    @Override
    public HttpInputMessage beforeBodyRead(
        HttpInputMessage inputMessage,
        MethodParameter parameter, Type targetType,
        Class<? extends HttpMessageConverter<?>> converterType) throws IOException {

        if (targetType.getTypeName().startsWith(Request.class.getTypeName())) {
            Request request = validateRequestThenGetRequest(inputMessage, charset, requestTimeout);
            ObjectMapper mapper = new ObjectMapper();
            return new MappingJacksonInputMessage(
                new ByteArrayInputStream(mapper.writeValueAsBytes(request)),
                inputMessage.getHeaders());
        } else if (CryptoDetector.decryptEnabled(parameter)) {
            return new DecryptHttpInputMessage(inputMessage, targetType, crypto, charset,
                requestTimeout);
        }

        return new MappingJacksonInputMessage(inputMessage.getBody(), inputMessage.getHeaders());
    }

    public static class DecryptHttpInputMessage implements HttpInputMessage {

        private HttpInputMessage inputMessage;
        private Type targetType;
        private Crypto crypto;
        private String charset;
        private Long cryptoTimeout;

        public DecryptHttpInputMessage(HttpInputMessage message, Type targetType, Crypto crypto,
            String charset, Long cryptoTimeout) {
            this.inputMessage = message;
            this.targetType = targetType;
            this.crypto = crypto;
            this.charset = charset;
            this.cryptoTimeout = cryptoTimeout;
        }

        @Override
        public InputStream getBody() throws IOException {
            Request request = validateRequestThenGetRequest(inputMessage, charset, cryptoTimeout);
            String decryptBody = crypto.decrypt(request.getEncrypt(), charset);
            if (log.isDebugEnabled()) {
                log.info("Decrypted Request Body: {}, target: {}", decryptBody, targetType);
            }

            if (decryptBody == null) {
                return null;
            }

            return new ByteArrayInputStream(decryptBody.getBytes(charset));
        }

        @Override
        public HttpHeaders getHeaders() {
            return inputMessage.getHeaders();
        }
    }
}
