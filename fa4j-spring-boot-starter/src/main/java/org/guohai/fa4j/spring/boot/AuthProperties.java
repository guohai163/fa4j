package org.guohai.fa4j.spring.boot;

import lombok.Data;
import org.guohai.fa4j.core.DecryptionEnum;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "gh.fa")
public class AuthProperties {
    /**
     * 验证用的KEY
     */
    private String validationKey ;

    /**
     * 加密用的KEY
     */
    private String decryptionKey ;

    /**
     * 加密算法，默认3DES，
     */
    private DecryptionEnum decryption = DecryptionEnum.AES;

    /**
     * 验签名算法
     */
    private String validation = "SHA1";

    /**
     * 指定序列化的格式，
     * false 为4.0之后的序列化格式
     * true 使用较旧的序列化格式。
     * 将此属性设置为 true 可能会带来安全风险。
     */
    private boolean useLegacyFormsAuthenticationTicketCompatibility = false;
}
