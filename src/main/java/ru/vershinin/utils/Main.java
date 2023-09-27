package ru.vershinin.utils;

import com.thoughtworks.xstream.XStream;

public class Main {
    public static void main(String[] args) {
        // Создаем экземпляр XStream
        XStream xstream = new XStream();
        xstream.allowTypesByWildcard(new String[]{"ru.vershinin.utils.**"});

        // Регистрируем класс CitResponse с алиасом "CIT_RESPONSE"
        xstream.processAnnotations(CitResponse.class);

        // XML-документ
        String xml = "<CIT_RESPONSE><SYSTEM><ERR Value=\"Значение_поля_ERR\"/></SYSTEM><DATA><BODY><messageId>Значение_поля_messageId</messageId></BODY></DATA></CIT_RESPONSE>";

        // Десериализуем XML в объект CitResponse
        CitResponse citResponse = (CitResponse) xstream.fromXML(xml);

        // Теперь у вас есть объект CitResponse, содержащий данные из XML
        System.out.println("Значение поля ERR: " + citResponse.getSYSTEM().getERR().getValue());
        System.out.println("Значение поля messageId: " + citResponse.getDATA().getBODY().getMessageId());
    }
}
