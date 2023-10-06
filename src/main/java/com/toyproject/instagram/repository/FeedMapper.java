package com.toyproject.instagram.repository;

import com.toyproject.instagram.entity.Feed;
import com.toyproject.instagram.entity.FeedImg;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface FeedMapper {

    public Integer saveFeed(Feed feed);
    public Integer saveFeedImgList(List<FeedImg> feedImgList);
}
