package demo;

import java.io.PrintStream;

import org.springframework.boot.Banner;
import org.springframework.boot.ExitCodeGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

//@Controller
//@EnableAutoConfiguration
public class SampleController implements ExitCodeGenerator{

//    @RequestMapping("/")
//    @ResponseBody
    String home() {
        return "32";
    }

    public static void main(String[] args) throws Exception {
        SpringApplication app = new SpringApplication(SampleController.class);
        app.setBanner(new MyBanner());
        app.run(args);
    }
    
    public static class MyBanner implements Banner{

        @Override
        public void printBanner(Environment arg0, Class<?> arg1, PrintStream arg2)
        {
            
        }
        
    }

    @Override
    public int getExitCode()
    {
        return 0;
    }
}