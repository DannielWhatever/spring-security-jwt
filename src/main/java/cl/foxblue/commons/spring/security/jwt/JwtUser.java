package cl.foxblue.commons.spring.security.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

/**
 *
 * Basic implementation of JWT user data
 *
 * @author daniel.gutierrez
 */
@Data @AllArgsConstructor
public class JwtUser implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String username;
    private final String roles; //roles could be a comma separated list



}
