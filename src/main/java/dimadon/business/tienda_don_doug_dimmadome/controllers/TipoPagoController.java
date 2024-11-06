package dimadon.business.tienda_don_doug_dimmadome.controllers;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dimadon.business.tienda_don_doug_dimmadome.entities.TipoPago;
import dimadon.business.tienda_don_doug_dimmadome.services.ServiceTipoPago;

@RestController
@RequestMapping("/tipoPago")
public class TipoPagoController {

    @Autowired
    ServiceTipoPago serviceTipoPago;

    @GetMapping("/obtener")
    public ArrayList<TipoPago> obtenerTipoPago() {
        return serviceTipoPago.obtnerTipoPago();
    }

    @PostMapping("/insertar")
    public TipoPago guardarTipoPago(@RequestBody TipoPago tipoPago) {
        return this.serviceTipoPago.insertarTipoPago(tipoPago);
    }

}
