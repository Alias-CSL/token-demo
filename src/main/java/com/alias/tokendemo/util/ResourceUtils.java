package com.alias.tokendemo.util;

import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;

/**
 * @ClassName ResourceUtils
 * @Description: 文件获取工具类
 * @Author ChenShengLi
 * @Date 2019/8/16
 **/
public class ResourceUtils {
    private ResourceBundle resourceBundle;

    public ResourceUtils(String resource) {
        this.resourceBundle = ResourceBundle.getBundle(resource);
    }

    public static ResourceUtils getResource(String fileName) {
        return new ResourceUtils(fileName);
    }

    public String getValue(String key, Object... args) {
        String temp = this.resourceBundle.getString(key);
        return MessageFormat.format(temp,args);
    }

    public Map<String, Object> getMap() {
        Map<String, Object> map = new HashMap<>();
        Iterator<String> iterator = this.resourceBundle.keySet().iterator();
        while(iterator.hasNext()) {
            String key = (String) iterator.next();
            Object value = this.resourceBundle.getString(key);
            map.put(key, value);
        }
        return map;
    }
}
