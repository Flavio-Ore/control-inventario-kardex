package dimadon.business.tienda_don_doug_dimmadome.controllers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dimadon.business.tienda_don_doug_dimmadome.entities.Usuario;
import dimadon.business.tienda_don_doug_dimmadome.security.JwtTokenProvider;
import dimadon.business.tienda_don_doug_dimmadome.services.ServiceUsuario;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private ServiceUsuario serviceUsuario;

    @PostMapping("/login")
    public ResponseEntity<HashMap<String, Object>> login(@RequestBody Map<String, String> loginRequest,
            HttpServletResponse response) {
        String email = loginRequest.get("email");
        String contrasena = loginRequest.get("contrasena");
        HashMap<String, Object> res = new HashMap<>();
        System.out.println("Intento de inicio de sesión con email: " + email + " y contraseña: " + contrasena);

        try {
            // Autenticación del usuario con las credenciales proporcionadas
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, contrasena));

            // Obtener el usuario desde la base de datos
            Usuario usuario = serviceUsuario.obtenerUsuarioPorEmail(email);

            if (usuario == null) {
                res.put("message", "Usuario no encontrado");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(res);
            }

            if (!"activo".equals(usuario.getEstado())) {
                res.put("message", "El usuario está inactivo");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(res);
            }

            // String token = jwtTokenProvider.generateToken(email,
            // usuario.getTipoUsuario().getIdTipoUsuario());
            // Configurar la cookie para el access token
            // Cookie tokenCookie = new Cookie("token", token);
            // tokenCookie.setHttpOnly(false);
            // tokenCookie.setSecure(true); // Establecer en true si usas HTTPS
            // tokenCookie.setPath("/");
            // tokenCookie.setMaxAge(60 * 10); // 5 minutos
            // response.addHeader("Access-Control-Allow-Credentials", "true");
            // Building cookies
            String token = jwtTokenProvider.generateToken(email, usuario.getTipoUsuario().getIdTipoUsuario());

            ResponseCookie tokenCookie = ResponseCookie.from("token", token)
                    .httpOnly(false)
                    .secure(true)
                    .sameSite("None")
                    .path("/")
                    .maxAge(24 * 60 * 60)
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, tokenCookie.toString());
            // response.addHeader("Access-Control-Allow-Credentials", "true");

            res.put("usuario", usuario);
            res.put("token", token);
            // Responder con un mensaje de éxito, sin mostrar los tokens en el cuerpo
            return ResponseEntity.status(HttpStatus.OK).body(res);
        } catch (BadCredentialsException e) {
            res.put("message", "Usuario o contraseña incorrecta");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(res);
        } catch (Exception e) {
            res.put("message", "Error interno del servidor");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(res);
        }
    }

    @PostMapping("/registro")
    public Usuario registrar(@RequestBody Usuario usuario) {
        return serviceUsuario.guardarUsuario(usuario);
    }
}