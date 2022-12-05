package com.secucom.securityservice;

import com.secucom.securityservice.config.RsaKeysConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@EnableConfigurationProperties(RsaKeysConfig.class)
class SecurityServiceApplicationTests {

	@Test
	void contextLoads() {
	}

}
