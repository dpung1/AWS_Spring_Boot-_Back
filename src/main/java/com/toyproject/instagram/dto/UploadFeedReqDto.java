package com.toyproject.instagram.dto;


import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Data
public class UploadFeedReqDto {
    private String content;
    private List<MultipartFile> files;
}
