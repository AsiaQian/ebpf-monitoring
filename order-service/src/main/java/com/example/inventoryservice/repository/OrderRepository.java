package com.example.inventoryservice.repository;

import com.example.inventoryservice.model.Order;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
    // 可以添加自定义查询方法，例如：
    List<Order> findByItemName(String itemName);
    List<Order> findByStatus(String status);
}