package com.toyproject.instagram.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class FeedImg {
    private int feedImgId;
    private int feedId;
    private String originFileName;
    private String saveFileName;
}
