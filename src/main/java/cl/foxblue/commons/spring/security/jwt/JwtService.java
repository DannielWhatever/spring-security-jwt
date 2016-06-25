package cl.foxblue.commons.spring.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/**
 * @author daniel.gutierrez
 */
@Service
public class JwtService {

    private static final String USERNAME = "username";
    private static final String ROL = "roles";

    @Value("${jwt.secret}") private String secret;

    /**
     * Tries to parse specified String as a JWT token. If successful, returns User object with username, id and role prefilled (extracted from token).
     * If unsuccessful (token is invalid or not containing all required user properties), simply returns null.
     *
     * @param token the JWT token to parse
     * @return the User object extracted from specified token or null if a token is invalid.
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


    public boolean validateToken(String token, UserDetails userDetails){
        JwtUser jwtUser = parseToken(token);

        return jwtUser.getUsername().equals(userDetails.getUsername());
    }

    /**
     * Generates a JWT token containing username as subject, and userId and role as additional claims. These properties are taken from the specified
     * User object. Tokens validity is infinite.
     *
     * @param user the user for which the token will be generated
     * @return the JWT token
     */
    public String generateToken(JwtUser user) {
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put(USERNAME, user.getUsername());
        claims.put(ROL, user.getRol());

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret)
                //expiration
                .compact();
    }



}