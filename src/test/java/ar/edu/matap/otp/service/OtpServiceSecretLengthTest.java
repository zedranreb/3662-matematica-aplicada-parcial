
package ar.edu.matap.otp.service;

import ar.edu.matap.otp.crypto.Base32;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OtpServiceSecretLengthTest {

    @Test
    void debeRechazarSecretoDe80Bits() {
        OtpService service = new OtpService();

        String secreto = crearSecretoDeBytes(10);

        assertThrows(IllegalArgumentException.class,
                () -> service.setSecret(secreto),
                "Un secreto de 80 bits debe ser rechazado");
    }

    @Test
    void debeRechazarSecretoDe120Bits() {
        OtpService service = new OtpService();

        String secreto = crearSecretoDeBytes(15);

        assertThrows(IllegalArgumentException.class,
                () -> service.setSecret(secreto),
                "Un secreto de 120 bits debe ser rechazado");
    }

    @Test
    void debeAceptarSecretoDe128Bits() {
        OtpService service = new OtpService();

        String secreto = crearSecretoDeBytes(16);

        assertDoesNotThrow(() -> service.setSecret(secreto));

        assertEquals(16,
                ((Number) service.state()
                        .get("secretBytes")).intValue());
    }

    @Test
    void debeAceptarSecretoDe160Bits() {
        OtpService service = new OtpService();

        String secreto = crearSecretoDeBytes(20);

        assertDoesNotThrow(() -> service.setSecret(secreto));

        assertEquals(20,
                ((Number) service.state()
                        .get("secretBytes")).intValue());
    }

    @Test
    void debeRechazarBase32Invalido() {
        OtpService service = new OtpService();

        assertThrows(IllegalArgumentException.class,
                () -> service.setSecret("ABC!123"));
    }

    // Genera claves reproducibles para probar sus longitudes.
    // No se utiliza para generar secretos seguros de producción.
    private String crearSecretoDeBytes(int cantidad) {
        byte[] bytes = new byte[cantidad];

        for (int i = 0; i < cantidad; i++) {
            bytes[i] = (byte) (i + 1);
        }

        return Base32.encode(bytes);
    }
}
