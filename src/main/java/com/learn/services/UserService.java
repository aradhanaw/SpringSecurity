package com.learn.services;

import com.learn.models.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {
    List<User> list = new ArrayList<>();

    public UserService() {
        list.add(new User("aara","aara","ara@gmail.com"));
        list.add(new User("abc","abcxyz","abcxyz@gmail.com"));

    }

    //get all users
    public List<User> getAllUsers() {
        return this.list;
    }

    //get single user
    public User getUser(String username)
    {
        return this.list.stream().filter((user)->user.getUsername().equals(username)).findAny().orElse(null);
    }
    //add new user
    public User addUser(User user)
    {
        this.list.add(user);
        return user;
    }
}
