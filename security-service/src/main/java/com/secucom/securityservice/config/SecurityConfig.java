package com.secucom.securityservice.config;



import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


//Pour specifier qu'il s'agit d'une classe de configuration'
@Configuration
//Pour specifier à spring où se trouve la configuration web
@EnableWebSecurity
public class SecurityConfig {
    //pour l'injection de dependance
    private RsaKeysConfig rsaKeysConfig;

    public SecurityConfig(RsaKeysConfig rsaKeysConfig) {
        this.rsaKeysConfig = rsaKeysConfig;
    }

    //c'est dans cette methode qu'on va specifier les utilisateurs qui ont droit à accéder à l'application
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(){
        return new InMemoryUserDetailsManager(
                //si vous ne voulez pas utiliser de passwordEncoder(qui permet d'encoder le mot de passe) utiliser noop
                User.withUsername("user1").password("{noop}1234").authorities("User").build(),
                User.withUsername("user2").password("{noop}1234").authorities("Admin").build(),
                User.withUsername("admin").password("{noop}1234").authorities("User","ADMIN").build()

        );

    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf->csrf.disable())
                //pour specifier aue toutes les requettes necessite une authentification
                .authorizeHttpRequests(auth->auth.anyRequest().authenticated())
                .sessionManagement(sess->sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //pour generer un token jwt on ajoute  oauth2resourceServer
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                //Le Basic Authentification  consiste à envoyer un nom d'utilisateur et un mot de passe
                .httpBasic(Customizer.withDefaults())
                .build();

    }
    //c'est lui qui va nous permettre de generer un token
    //pour signer un token on a besoin de publiKey et privateKey
    @Bean
     JwtEncoder jwtEncoder(){
        JWK jwk=new RSAKey.Builder(rsaKeysConfig.publicKey()).privateKey(rsaKeysConfig.privateKey()).build();
        JWKSource<SecurityContext> jwkSource= new ImmutableJWKSet<>(new JWKSet(jwk));
        return  new NimbusJwtEncoder(jwkSource);

    }
    //pour verifier la signature on a besoin que de publicKey
    @Bean
     JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeysConfig.publicKey()).build();
    }
    //lien pour telecharger openssl si on ne l'a pas il faut aussi l'ajouter le chemain d'accès etant dans dans bin dans la variable d'environnement
    //https://slproweb.com/products/Win32OpenSSL.html
    //dans ressources creer un dossier ouvrir ce dossier avec le terminal et taper les 3 commandes qui suivent:
    // openssl genrsa -out keypair.pem 2048
    //  openssl rsa -in keypair.pem -pubout -out public.pem
    // openssl pkcs8 -topk8 -inform PEM -nocrypt -in keypair.pem -out private.pem
}
