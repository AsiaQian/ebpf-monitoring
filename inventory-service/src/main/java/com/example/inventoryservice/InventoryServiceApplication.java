package com.example.inventoryservice;

import com.example.inventoryservice.model.Product;
import com.example.inventoryservice.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.event.EventListener;
import org.springframework.boot.context.event.ApplicationReadyEvent;

@SpringBootApplication
public class InventoryServiceApplication {

    @Autowired
    private ProductRepository productRepository;

    public static void main(String[] args) {
        SpringApplication.run(InventoryServiceApplication.class, args);
    }

    // 应用程序启动后初始化一些虚拟数据
    @EventListener(ApplicationReadyEvent.class)
    public void init() {
        if (productRepository.count() == 0) {
            System.out.println("Initializing dummy product data...");
            productRepository.save(new Product("Laptop", 100));
            productRepository.save(new Product("Mouse", 200));
            productRepository.save(new Product("Keyboard", 150));
            System.out.println("Dummy product data initialized.");
        }
    }
}