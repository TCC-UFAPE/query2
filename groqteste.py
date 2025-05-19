import os
import json
from groq import Groq
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

with open("config.json", "r", encoding="utf-8") as config_file:
    config = json.load(config_file)
    api_key = config["api_key"]

client = Groq(api_key=api_key)

prompt = (
    "You are a security researcher specialized in detecting security vulnerabilities.\n"
    "Provide the answer only in the following format:\n\n"
    "vulnerability: <YES or NO> | vulnerability type: N/A | vulnerability name: N/A | explanation: <explanation for the prediction>.\n"
    "Do not include anything else in the response.\n\n"
    "User: Is this code snippet subject to any security vulnerability?\n\n"
    "<CODE_SNIPPET>\n\n"
    "Answer:"
)

codigo = """
package securibench.micro.sanitizers;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import securibench.micro.BasicTestCase;
import securibench.micro.MicroTestCase;

public class Sanitizers1 extends BasicTestCase implements MicroTestCase {
    private static final String FIELD_NAME = "name";
    private PrintWriter writer;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter(FIELD_NAME);
        String clean = clean(name);
        
        writer = resp.getWriter();
        resp.setContentType("text/html");
        
        writer.println("<html>");
        writer.println("<b>" + name  + "</b>");                  			
        writer.println("<b>" + clean + "</b>");                  			
        writer.println("</html>");
        
    }
    
    private String clean(String name) {
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < name.length(); i++) {
            char ch = name.charAt(i);
            switch (ch) {
                case '<':
                    buf.append("&lt;"); break;
                case '>':
                    buf.append("&gt;"); break;
                case '&':
                    buf.append("&amp;"); break;
                default:
                    if(Character.isLetter(ch) || Character.isDigit(ch) || ch == '_') {
                        buf.append(ch);
                    } else {
                        buf.append('?');
                    }
            }
        }
        
        return buf.toString();
    }

    public String getDescription() {
        return "simple sanitization check";
    }
    
    public int getVulnerabilityCount() {
        return 1;
    }
}
"""

prompt = prompt.replace("<TRECHO_CODIGO>", codigo)

chat_completion = client.chat.completions.create(
    messages=[
        {"role": "system", "content": prompt},
        {"role": "user", "content": codigo},
    ],
    model="llama-3.3-70b-versatile",
    temperature=0,
)

print(chat_completion.choices[0].message.content)
