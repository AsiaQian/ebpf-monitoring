package com.example.inventoryservice.service;

import com.example.inventoryservice.model.Product;
import com.example.inventoryservice.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class InventoryService {

    private final ProductRepository productRepository;

    @Autowired
    public InventoryService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    public Optional<Product> getProductById(Long id) {
        return productRepository.findById(id);
    }

    public boolean checkStock(String itemName, int quantity) {
        // 从数据库检查库存 (Java 对 MySQL 的调用)
        Optional<Product> product = productRepository.findByItemName(itemName);
        return product.isPresent() && product.get().getStock() >= quantity;
    }

    public Product updateStock(String itemName, int newStock) {
        // 更新库存到数据库 (Java 对 MySQL 的调用)
        return productRepository.findByItemName(itemName)
                .map(product -> {
                    product.setStock(newStock);
                    return productRepository.save(product);
                })
                .orElse(null);
    }

    public Product addProduct(Product product) {
        return productRepository.save(product);
    }

    public void deleteProduct(Long id) {
        productRepository.deleteById(id);
    }
}