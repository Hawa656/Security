package com.secucom.securityservice.web;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
public class AuthController {
    //quand on va se connecter on aura besoin d'injecter jwtEncoder

    private JwtEncoder jwtEncoder;

    public AuthController(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping("/token")
    //on va crrer une methode qui permet de retourner le token
    public Map<String,String> jwtToken(Authentication authentication){
        Map<String,String> idToken=new HashMap<>();
        Instant instant=Instant.now();
        String scope = authentication.getAuthorities()
                //.stream().map(aut -> authentication.getName().collectors(Collectors.joining(""));
                .stream().map(aut->aut.getAuthority()).collect(Collectors.joining(""));
        JwtClaimsSet jwtClaimsSet= JwtClaimsSet.builder()
                .subject(Authentication.class.getName())
                //c'est à dire le token est generer à quelle date
                .issuedAt(instant)
                //date d'expiration
                .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                //l'application qui a generer le token
                .issuer("Secucom")
                //pour les rôles
                //scope represente les rôles
                .claim("scope",scope)
                .build();
        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken",jwtAccessToken);
        return idToken;
    }
}
