package com.liangfan.main.auth;


import com.liangfan.main.util.SimpleRequestParam;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.http.NameValuePair;

import java.io.File;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignatureParam implements Comparable<SignatureParam>, NameValuePair {

    private String name;
    private String value;
    private File file;
    public SignatureParam(String name,String value){
        this.name=name;
        this.value=value;
    }
    public SignatureParam(NameValuePair pair){
        this.name=pair.getName();
        this.value=pair.getValue();
    }

    public SignatureParam(String name,File file){
        assert file!=null;
        this.name=name;
        this.file=file;
        this.value=file.getName();
    }
    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getValue() {
        return this.value;
    }
    public boolean isFile(){
        return this.file!=null;
    }
    @Override
    public int compareTo(SignatureParam o) {
        if(this.getName().compareTo(o.name)==0){
            return this.getValue().compareTo(o.value);
        }
        return this.getName().compareTo(o.name);
    }

    public static boolean hasFile(final List<SignatureParam> params) {
        if (params==null||params.isEmpty()) {
            return false;
        }
        boolean containsFile = false;
        for (final SignatureParam param : params) {
            if (param.isFile()) {
                containsFile = true;
                break;
            }
        }
        return containsFile;
    }
}
