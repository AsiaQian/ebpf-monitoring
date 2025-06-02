package com.example.inventoryservice.service;

import com.example.inventoryservice.model.Order;
import com.example.inventoryservice.repository.OrderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Optional;

@Service
public class OrderService {

    private final OrderRepository orderRepository;
    private final RestTemplate restTemplate; // 用于调用其他服务

    // 通过构造函数注入依赖
    @Autowired
    public OrderService(OrderRepository orderRepository, RestTemplate restTemplate) {
        this.orderRepository = orderRepository;
        this.restTemplate = restTemplate;
    }

    public List<Order> getAllOrders() {
        // 直接从数据库获取所有订单
        return orderRepository.findAll();
    }

    public Optional<Order> getOrderById(Long id) {
        // 从数据库获取特定订单
        return orderRepository.findById(id);
    }

    public Order createOrder(String itemName, int quantity) {
        // 1. 调用 inventory-service 检查库存 (Java 应用间调用)
        String inventoryServiceUrl = "http://inventory-service:8081/api/inventory/checkStock";
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(inventoryServiceUrl)
                .queryParam("itemName", itemName)
                .queryParam("quantity", quantity);

        String inventoryResponse = null;
        try {
            inventoryResponse = restTemplate.getForObject(builder.toUriString(), String.class);
        } catch (Exception e) {
            System.err.println("Error calling inventory-service: " + e.getMessage());
            // 实际应用中应该抛出自定义异常或返回特定错误码
            return new Order(itemName, quantity, "INVENTORY_CHECK_FAILED");
        }


        if (inventoryResponse != null && inventoryResponse.contains("In stock")) {
            // 2. 库存充足，保存订单到数据库 (Java 对 MySQL 的调用)
            Order newOrder = new Order(itemName, quantity, "COMPLETED");
            return orderRepository.save(newOrder);
        } else {
            // 3. 库存不足
            System.out.println("Inventory check failed for " + itemName + ". Response: " + inventoryResponse);
            return new Order(itemName, quantity, "OUT_OF_STOCK");
        }
    }

    public Order updateOrderStatus(Long id, String status) {
        return orderRepository.findById(id)
                .map(order -> {
                    order.setStatus(status);
                    return orderRepository.save(order);
                })
                .orElse(null);
    }

    public void deleteOrder(Long id) {
        orderRepository.deleteById(id);
    }
}