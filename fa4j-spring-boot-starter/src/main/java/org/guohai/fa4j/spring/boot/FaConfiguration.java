package org.guohai.fa4j.spring.boot;

import org.guohai.fa4j.core.DecryptionEnum;
import org.guohai.fa4j.core.FormsAuthentication;
import org.guohai.fa4j.core.HashProvider;
import org.guohai.fa4j.core.MachineKeySection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Configuration
@EnableConfigurationProperties(AuthProperties.class)
@ComponentScan("org.guohai.fa4j.spring.boot")
public class FaConfiguration {

    @Autowired
    AuthProperties authProperties;

    /**
     * 向SB容器中注册 FormsAuthentication
     * @return
     */
    @Bean
    FormsAuthentication formsAuthentication() throws Exception {
        if(authProperties.getDecryptionKey() == null || authProperties.getValidationKey()==null){
            throw new NullPointerException("DecryptionKey or ValidationKey is null");
        }
        HashProvider hashProvider = new HashProvider(authProperties.getValidationKey());
        MachineKeySection machineKeySection = new MachineKeySection(authProperties.getDecryptionKey(), authProperties.getDecryption());
        return new FormsAuthentication(machineKeySection, hashProvider, authProperties.isUseLegacyFormsAuthenticationTicketCompatibility());
    }
}