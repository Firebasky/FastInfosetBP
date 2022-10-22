package burp;

import burp.utils.Transfer;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * 菜单类，负责显示菜单，处理菜单事件
 */
public class Menu implements IContextMenuFactory {
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList();
        JMenu FastMenu = new JMenu("FastInfoset-converter");
        JMenuItem encode = new JMenuItem("Encoding request body");
        JMenuItem decode = new JMenuItem("Decoding request body");
        FastMenu.add(encode);
        FastMenu.add(decode);
        FastMenu.addSeparator();
        //若数据包无法编辑，则将编码解码菜单项设置为禁用
        if(invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST){
            encode.setEnabled(false);
            decode.setEnabled(false);
        }

        // 编码
        encode.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent arg0) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(iReqResp.getRequest());
                // 不对GET请求进行编码
                if(!reqInfo.getMethod().equals("POST")){
                    JOptionPane.showConfirmDialog(null,"GET requests cannot be chunked encoded！","Warning",JOptionPane.CLOSED_OPTION,JOptionPane.WARNING_MESSAGE);
                    return;
                }

                // 不重复编码
                if(Transfer.isFastInFoSet(iReqResp)){
                    JOptionPane.showConfirmDialog(null,"The request has been chunked encoded，Do not repeat the encoding！","Warning",JOptionPane.CLOSED_OPTION,JOptionPane.WARNING_MESSAGE);
                    return;
                }

                //
                try {
                    byte[] request =Transfer.encoding(iReqResp);
                    if (request != null) {
                        iReqResp.setRequest(request);
                    }
                } catch (Exception e) {
                    BurpExtender.stderr.println(e.getMessage());
                }
            }
        });

        //解码
        decode.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent arg0) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];

                // 进制对未编码请求解码
                if(!Transfer.isFastInFoSet(iReqResp)){
                    JOptionPane.showConfirmDialog(null,"The request is unencoded and cannot be decoded!","Warning",JOptionPane.CLOSED_OPTION,JOptionPane.WARNING_MESSAGE);
                    return;
                }

                try {
                    byte[] request = Transfer.decoding(iReqResp);
                    if (request != null) {
                        iReqResp.setRequest(request);
                    }
                } catch (Exception e) {
                    BurpExtender.stderr.println(e.getMessage());
                }
            }
        });
        menus.add(FastMenu);
        return menus;
    }
}