package cl.foxblue.commons.spring.security.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

/**
 *
 *
 * @author daniel.gutierrez
 */
@Data @AllArgsConstructor
public class JwtUser implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String username;
    private final String rol;



}
