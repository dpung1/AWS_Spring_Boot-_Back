package com.toyproject.instagram.service;

import com.toyproject.instagram.dto.UploadFeedReqDto;
import com.toyproject.instagram.entity.Feed;
import com.toyproject.instagram.entity.FeedImg;
import com.toyproject.instagram.repository.FeedMapper;
import com.toyproject.instagram.security.PrincipalUser;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class FeedService {

    @Value("${file.path}")
    private String filePath;

    private final FeedMapper feedMapper;

    @Transactional( rollbackFor = Exception.class )
    public void upload(UploadFeedReqDto uploadFeedReqDto) {
        String content = uploadFeedReqDto.getContent();
        List<FeedImg> feedImgList = new ArrayList<>();
        PrincipalUser principalUser =
                (PrincipalUser)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = principalUser.getUsername();

        Feed feed = Feed.builder()
                .content(content)
                .username(username)
                .build();

        feedMapper.saveFeed(feed);

        uploadFeedReqDto.getFiles().forEach(file -> {
            String originName = file.getOriginalFilename();
            String extensionName = originName.substring(originName.lastIndexOf("."));
            String saveName = UUID.randomUUID().toString().replace("-","").concat(extensionName);

            Path uploadPath = Paths.get(filePath + "/feed/" + saveName);

            File f = new File(filePath + "/feed");
            if(!f.exists()) {
                f.mkdirs(); // 경로에 파일이 없으면 폴더를 만들어라
            }

            try {
                Files.write(uploadPath, file.getBytes());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            feedImgList.add(FeedImg.builder()
                        .feedId(feed.getFeedId())
                        .originFileName(originName)
                        .saveFileName(saveName)
                        .build());
        });

        feedMapper.saveFeedImgList(feedImgList);
    }
}
