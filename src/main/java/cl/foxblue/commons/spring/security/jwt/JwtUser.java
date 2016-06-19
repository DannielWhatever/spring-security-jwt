package cl.foxblue.commons.spring.security.jwt;

import java.io.Serializable;

/**
 * @author daniel.gutierrez
 */
public class JwtUser implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String username;
    private final String rol;

    public JwtUser(String username, String rol) {
        this.username = username;
        this.rol = rol;
    }


    public String getUsername() {
        return username;
    }

    public String getRol() {
        return rol;
    }

}
