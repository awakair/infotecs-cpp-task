# Тестовое задание на стажировку в ИнфоТеКС
На которую, я не прошел, потому что:
> Нам понравилось ваше задание и планировали пригласить вас на собеседование, но, к сожалению, уже определились с финальным кандидатом.
> Спасибо вам за участие в отборе, конкуренция на данное направление была очень высокая, можете попробовать свои силы на следующем отборе в июле 🙂

Пусть останется в истории.

## Программа №1 комплекса программ:
Должна реализовать функционал классификации сетевых пакетов, для этого она должна проделать следующие действия:
1.	С помощью библиотеки libpcap (либо другой на выбор разработчика) прочитать пакеты из pcap файла. Возможность захвата пакетов с сетевого интерфейса будет дополнительным преимуществом при оценивании. 
2.	Выделить из них заголовки IP пакетов и заголовки TCP|UDP.
3.	Из выделенных заголовков прочитать IP адреса и порты.
4.	Каждый пакет классифицировать к потоку (совокупности пакетов от IP адреса №1 до IP адреса №2 с уникальной комбинацией портов).
5.	В каждом потоке посчитать количество пакетов и количество переданных байт.
6.	После завершения чтения всех пакетов информацию о всех выделенных потоках необходимо записать в CSV файл.
Примечание №1 по Программе №1: Необходимо классифицировать только IPv4 пакеты.

## Мое решение
Использовалась библиотека [PcapPlusPlus](https://pcapplusplus.github.io), т.к. `libpcap` это библиотека на языке C,
которая сама никак не реализует ООП, поэтому для написания программы "в ООП стиле" пришлось бы писать обертку вокруг нее
`PcapPlusPlus` является ООП оберткой вокруг нескольких библиотек, включая `libpcap`/`winpcap`,
эти возможности и использовались
Код писался, используя [Google C++ Code Style](https://google.github.io/styleguide/cppguide.html)
### Usage
```bash
Test task for infotecs. Program № 1
Usage:
        --source-name <name>    Name of source file or interface
        --source-type <pcap-file/interface>     pcap-file if you want to process pcap-fileor interface if you want to listen interface
        --output-file <name>    Output .csv file. In will be created or rewritten
        --timeout       Timeout to listen interface (seconds). Ingored for pcap-file option
Examples:
        stream-classifier --source-name captured.pcap --source-type pcap-file --output-file stats.csv
        stream-classifier --source-name eth0 --source-type interface --output-file stats.csv --timeout 500
```
