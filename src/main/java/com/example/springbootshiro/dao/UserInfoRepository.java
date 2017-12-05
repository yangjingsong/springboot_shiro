package com.example.springbootshiro.dao;

import com.example.springbootshiro.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Created by yjs on 2017/12/4.
 */
public interface UserInfoRepository extends JpaRepository<UserInfo,Integer> {
    UserInfo findByUsername(String username);
}
