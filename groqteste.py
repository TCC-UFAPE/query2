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
    "Você é um pesquisador de segurança especializado em detectar vulnerabilidades de segurança.\n"
    "Forneça a resposta apenas no seguinte formato:\n\n"
    "vulnerabilidade: <SIM ou NÃO> | tipo de vulnerabilidade: N/A | nome da vulnerabilidade: N/A | explicação: <explicação para a previsão>.\n"
    "Não inclua mais nada na resposta.\n\n"
    "Usuário: Este trecho de código está sujeito a alguma vulnerabilidade de segurança?\n\n"
    "<TRECHO_CODIGO>\n\n"
    "Resposta:"
)

codigo = """
package securibench.micro.aliasing;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import securibench.micro.BasicTestCase;
import securibench.micro.MicroTestCase;

public class Aliasing1 extends BasicTestCase implements MicroTestCase {
	private static final String FIELD_NAME = "name";

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
       String name = req.getParameter(FIELD_NAME);
       String str = name;
              
       PrintWriter writer = resp.getWriter();
       writer.println(str);                             
    }
    
    public String getDescription() {
        return "simple test of field assignment";
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
