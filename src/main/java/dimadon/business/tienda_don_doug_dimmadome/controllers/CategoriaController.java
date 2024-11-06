package dimadon.business.tienda_don_doug_dimmadome.controllers;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dimadon.business.tienda_don_doug_dimmadome.entities.Categoria;
import dimadon.business.tienda_don_doug_dimmadome.services.ServiceCategoria;

@RestController
@RequestMapping("/categoria")
public class CategoriaController {

    @Autowired
    ServiceCategoria serviceCategoria;

    @GetMapping("/obtener")
    public ArrayList<Categoria> obtenerCategoria() {
        return serviceCategoria.obtnerCategoria();
    }

    @PostMapping("/insertar")
    public Categoria guardarCategoria(@RequestBody Categoria categoria) {
        return this.serviceCategoria.insertarCategoria(categoria);
    }
}
