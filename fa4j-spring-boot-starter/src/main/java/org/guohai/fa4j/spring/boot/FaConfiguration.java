package org.guohai.fa4j.spring.boot;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(AuthProperties.class)
@ComponentScan("org.guohai.fa4j.spring.boot")
public class FaConfiguration {
    
}