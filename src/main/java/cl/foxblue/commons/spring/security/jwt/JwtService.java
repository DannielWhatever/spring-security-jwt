package cl.foxblue.commons.spring.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/**
 *
 * Don't forget to provide the jwt secret.
 *
 * @author daniel.gutierrez
 */
@Service
public class JwtService {

    private static final String USERNAME = "username";
    private static final String ROL = "roles";

    @Value("${jwt.secret}") private String secret;

    /**
     * Tries to get JwtUser from received token.
     *
     * @param token
     * @return jwtUser
     */
    public JwtUser parseToken(String token) {
        try {
            Claims body = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();

            return new JwtUser(
                    (String) body.get(USERNAME),
                    (String) body.get(ROL));

        } catch (JwtException | ClassCastException e) {
            return null;
        }
    }

    /**
     * Generate the token from a JwtUser object.
     *
     * @param jwtUser
     * @return the JWT token
     */
    public String generateToken(JwtUser jwtUser) {
        Claims claims = Jwts.claims().setSubject(jwtUser.getUsername());
        claims.put(USERNAME, jwtUser.getUsername());
        claims.put(ROL, jwtUser.getRoles());

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret)
                //expiration
                .compact();
    }


    /**
     * Valid that the token belong to the user.
     *
     * @param token
     * @param userDetails
     * @return boolean
     */
    public boolean validateToken(String token, UserDetails userDetails){
        return parseToken(token)
                .getUsername()
                .equals(userDetails.getUsername());
    }





}