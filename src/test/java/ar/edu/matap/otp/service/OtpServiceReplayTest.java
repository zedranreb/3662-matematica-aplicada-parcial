
package ar.edu.matap.otp.service;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OtpServiceReplayTest {

    @Test
    void noDebeAceptarDosVecesElMismoTotp()  throws InterruptedException {
        OtpService service = new OtpService();
        service.setSecret(OtpService.RFC_SECRET);

        Map<String, Object> token = obtenerTotpConMargen(service);

        String codigo = (String) token.get("code");

        Map<String, Object> primera =
                service.verify("TOTP", codigo);

        Map<String, Object> segunda =
                service.verify("TOTP", codigo);

        assertEquals(true, primera.get("valid"),
                "La primera validación debe ser aceptada");

        assertEquals(false, segunda.get("valid"),
                "El mismo TOTP no debe aceptarse dos veces");
    }


    @Test
    void reaplicarMismoSecretoNoDebePermitirReutilizarTotp()  throws InterruptedException {
        OtpService service = new OtpService();
        service.setSecret(OtpService.RFC_SECRET);

        Map<String, Object> token = obtenerTotpConMargen(service);

        String codigo = (String) token.get("code");

        Map<String, Object> primera =
                service.verify("TOTP", codigo);

        assertEquals(true, primera.get("valid"));

        // Se vuelve a aplicar exactamente el mismo secreto.
        service.setSecret(OtpService.RFC_SECRET);

        Map<String, Object> segunda =
                service.verify("TOTP", codigo);

        assertEquals(false, segunda.get("valid"),
                "Reaplicar el mismo secreto no debe habilitar un TOTP ya utilizado");
    }


    @Test
    void volverASecretoAnteriorNoDebeRehabilitarTotpUsado()  throws InterruptedException {
        OtpService service = new OtpService();

        // Configuramos el secreto A.
        service.setSecret(OtpService.RFC_SECRET);

        Map<String, Object> token = obtenerTotpConMargen(service);

        String codigo = (String) token.get("code");

        // Primera validación: debe ser aceptada.
        Map<String, Object> primera =
                service.verify("TOTP", codigo);

        assertEquals(true, primera.get("valid"));

        // Cambiamos a un secreto B y volvemos al secreto A.
        service.newRandomSecret();
        service.setSecret(OtpService.RFC_SECRET);

        // Comprobamos que seguimos en el mismo intervalo.
        Assumptions.assumeTrue(
                codigo.equals(service.currentTotp().get("code")),
                "Reejecutar: cambió el intervalo TOTP");

        // El código de A ya fue usado y no debería rehabilitarse.
        Map<String, Object> segunda =
                service.verify("TOTP", codigo);

        assertEquals(false, segunda.get("valid"),
                "Volver al secreto A no debe rehabilitar un TOTP ya utilizado");
    }


    private Map<String, Object> obtenerTotpConMargen(OtpService service)
            throws InterruptedException {

        Map<String, Object> token = service.currentTotp();
        long restante = (Long) token.get("remainingMs");

        // Si quedan 10 segundos o menos, esperamos el siguiente intervalo.
        if (restante <= 10000) {
            Thread.sleep(restante + 200);
            token = service.currentTotp();
        }

        assertTrue((Long) token.get("remainingMs") > 10000,
                "Debe quedar tiempo suficiente para ejecutar la prueba");

        return token;
    }


    @Test
    void resetearContadoresNoDebeRehabilitarTotpUsado()
            throws InterruptedException {

        OtpService service = new OtpService();
        service.setSecret(OtpService.RFC_SECRET);

        Map<String, Object> token = obtenerTotpConMargen(service);
        String codigo = (String) token.get("code");

        // Validamos correctamente el TOTP por primera vez.
        Map<String, Object> primera =
                service.verify("TOTP", codigo);

        assertEquals(true, primera.get("valid"),
                "La primera validación debe ser aceptada");

        // Reiniciamos los contadores HOTP.
        service.resetCounters();

        // Verificamos que no haya cambiado el intervalo TOTP.
        long intervaloInicial =
                ((Number) token.get("epochSeconds")).longValue()
                        / OtpService.PERIOD;

        long intervaloActual =
                ((Number) service.currentTotp().get("epochSeconds"))
                        .longValue() / OtpService.PERIOD;

        Assumptions.assumeTrue(intervaloInicial == intervaloActual,
                "Reejecutar: cambió el intervalo TOTP");

        // El código TOTP utilizado debe seguir rechazándose.
        Map<String, Object> segunda =
                service.verify("TOTP", codigo);

        assertEquals(false, segunda.get("valid"),
                "Reiniciar los contadores HOTP no debe rehabilitar un TOTP usado");
    }


    @Test
    void debeAceptarTotpDeUnNuevoIntervalo()
            throws InterruptedException {

        OtpService service = new OtpService();
        service.setSecret(OtpService.RFC_SECRET);

        // Obtenemos un TOTP con tiempo suficiente.
        Map<String, Object> tokenInicial =
                obtenerTotpConMargen(service);

        String codigoInicial =
                (String) tokenInicial.get("code");

        long intervaloInicial =
                ((Number) tokenInicial.get("epochSeconds"))
                        .longValue() / OtpService.PERIOD;

        // Validamos el primer código.
        Map<String, Object> primera =
                service.verify("TOTP", codigoInicial);

        assertEquals(true, primera.get("valid"),
                "El primer TOTP debe ser aceptado");

        // Esperamos a que finalice el intervalo actual.
        long restante =
                ((Number) service.currentTotp()
                        .get("remainingMs")).longValue();

        Thread.sleep(restante + 200);

        // Obtenemos el TOTP correspondiente al nuevo intervalo.
        Map<String, Object> tokenNuevo =
                service.currentTotp();

        long intervaloNuevo =
                ((Number) tokenNuevo.get("epochSeconds"))
                        .longValue() / OtpService.PERIOD;

        assertTrue(intervaloNuevo > intervaloInicial,
                "Debe haber comenzado un nuevo intervalo TOTP");

        String codigoNuevo =
                (String) tokenNuevo.get("code");

        // El servidor debe aceptar el código del nuevo intervalo.
        Map<String, Object> segunda =
                service.verify("TOTP", codigoNuevo);

        assertEquals(true, segunda.get("valid"),
                "Un TOTP de un intervalo nuevo debe ser aceptado");
    }

}
