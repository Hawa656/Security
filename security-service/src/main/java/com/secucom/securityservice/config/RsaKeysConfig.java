package com.secucom.securityservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
//c'est comme si on disait va vers le fichier application.propertise et
//tu vas chercher toute les propriétés qui commencent par "rsa", tu me recupere les valeurs
//et tu vas les injecter directement dans ces variables
@ConfigurationProperties(prefix = "rsa")
public record RsaKeysConfig(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
}
