package com.toyproject.instagram.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Feed {
    private int feedId;
    private String content;
    private String username;
    private LocalDateTime create_date;
    private List<FeedImg> feedImgList;


}
