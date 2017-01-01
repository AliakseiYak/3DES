/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author admin
 */
@WebServlet(urlPatterns = {"/GetPinBlock"})
public class GetPinBlock extends HttpServlet {
    
    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String pin, cardNumber, key;
        Map<String, String> queryParams;
        queryParams = getQueryParameters(request);
        pin = queryParams.get("pin");
        cardNumber = queryParams.get("card_number");
        key = queryParams.get("key");
        
        String encodedValue;
        
        try {
            encodedValue = (encrypt3DES(pin,cardNumber,key)!=null ? encrypt3DES(pin,cardNumber,key) : "Error");
        } catch (Exception ex) {
            encodedValue = "Error";
        }
                    
        response.setContentType("text/plain");
        try (PrintWriter out = response.getWriter()) {
            
            out.println(encodedValue);
        }         
    }
     public String encrypt3DES(String pin, String cardNum, String encriptionKey) throws Exception {
        
            byte[] cipherText = null;
       try {
            String convertedPin = "04TTTTFFFFFFFFFF".replaceAll("TTTT", pin);
            byte[] convertedPinByteArray = hexStringToByteArray(convertedPin);
            
            String convertedCardNum = "0000".concat(cardNum.substring(3, 15));
            byte[] convertedCardByteArray = hexStringToByteArray(convertedCardNum);
        //    System.out.println(convertedCardNum);
            
            byte[] messByteArr = new byte[convertedPinByteArray.length];
            int i = 0;
            for (byte b : convertedCardByteArray)
                messByteArr[i] = (byte) (b ^ convertedPinByteArray[i++]);
         //   System.out.println(byteArrToHexString(messByteArr));
            
            byte[] keyByteArr = hexStringToByteArray(encriptionKey);
            
            final SecretKey key = new SecretKeySpec(keyByteArr, "DESede");
            Cipher cipher;
            
            Security.addProvider(new BouncyCastleProvider());
            cipher = Cipher.getInstance("DESede/ECB/Nopadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            

            cipherText = cipher.doFinal(messByteArr);
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            cipherText=null;
        }
       return byteArrToHexString(cipherText);
     
    }
   
    public static String byteArrToHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] hexStringToByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>
       
    public static Map<String, String> getQueryParameters(HttpServletRequest request) {
        Map<String, String> queryParameters = new HashMap<>();
        String queryString = request.getQueryString();

        if (queryString.isEmpty()) {
            return queryParameters;
        }

        String[] parameters = queryString.split("&");

        for (String parameter : parameters) {
            String[] keyValuePair = parameter.split("=");
            if (keyValuePair.length == 1){
                queryParameters.put(keyValuePair[0], "");           
            }else{
                queryParameters.put(keyValuePair[0], keyValuePair[1]);
            }
        }
        return queryParameters;
    }
    
}


