// Word lists behind the entity recogniser (src/entities.ts).
//
// A PII model learns that "Alice Johnson" is a person and "Machine Learning" is
// not from millions of examples. Without a model, the same evidence comes from
// small lists: common given names and surnames across the library's 24
// languages, names that are also ordinary words, and capitalised words that
// start sequences which are not people (places, organisations, products, the
// first word of a sentence). The lists only adjust a score; a cue such as
// "my name is" still finds a name that appears in none of them.

const words = (list: string): ReadonlySet<string> => new Set(list.split(/\s+/).filter(Boolean));

export const GIVEN_NAMES = words(`
James John Robert Michael William David Richard Joseph Thomas Charles Christopher Daniel Matthew Anthony
Donald Steven Paul Andrew Joshua Kenneth Kevin Brian George Timothy Ronald Edward Jason Jeffrey Ryan Jacob
Gary Nicholas Eric Jonathan Stephen Larry Justin Scott Brandon Benjamin Samuel Gregory Alexander Patrick
Raymond Jack Dennis Jerry Tyler Aaron Adam Nathan Henry Zachary Douglas Peter Kyle Noah Ethan Jeremy
Walter Christian Keith Roger Terry Austin Sean Gerald Carl Harold Dylan Arthur Lawrence Jordan Jesse Bryan
Billy Bruce Gabriel Joe Logan Alan Albert Willie Elijah Wayne Randy Vincent Liam Oliver Lucas Mason Owen
Leo Harry Oscar Charlie Freddie Alfie Archie Theo Isaac Mary Patricia Jennifer Linda Elizabeth Barbara
Susan Jessica Sarah Karen Lisa Nancy Betty Sandra Margaret Ashley Kimberly Emily Donna Michelle Carol Amanda
Melissa Deborah Stephanie Dorothy Rebecca Sharon Laura Cynthia Amy Kathleen Angela Shirley Brenda Emma Anna
Pamela Nicole Samantha Katherine Christine Helen Debra Rachel Carolyn Janet Maria Catherine Heather Diane
Olivia Julie Joyce Victoria Ruth Virginia Lauren Kelly Christina Joan Evelyn Judith Andrea Hannah Megan
Cheryl Jacqueline Martha Madison Teresa Gloria Sara Janice Ann Kathryn Abigail Sophia Frances Jean Alice
Judy Isabella Julia Grace Amber Denise Danielle Marilyn Beverly Charlotte Natalie Theresa Diana Brittany
Doris Kayla Alexis Lori Marie Ava Mia Amelia Harper Ella Chloe Zoe Lily Ellie Sophie Isla Freya Poppy Daisy
Ivy Florence Rosie Evie Matilda Phoebe Bob Bobby Tom Tim Jim Jimmy Mike Dave Steve Chris Nick Ben Dan
Danny Matt Alex Sam Tony Andy Joey Jake Josh Luke Ted Fred Ken Ron Rick Greg Kate Katie Liz Beth Jenny
Becky Sue Meg Anne Annie Kim Pam Tina Nina Rita Lucy Molly Holly Ruby Jane Dana Erin Tara Leah Nora Clara
Eva Ada Iris Rose Grant Ian Neil Colin Graham Craig Stuart Ross Martin Simon Philip Phillip Frank Ray
José Juan Luis Carlos Javier Miguel Antonio Manuel Francisco Jesús Pedro Alejandro Pablo Sergio Jorge
Alberto Fernando Rafael Ricardo Diego Andrés Raúl Enrique Ramón Mario Álvaro Óscar Rubén Iván Hugo Mateo
Santiago Sebastián Martín Nicolás Gonzalo Joaquín Emilio Ignacio Felipe Agustín Tomás Gustavo Eduardo
Rodrigo Vicente Lucía Sofía Martina Valentina Isabel Carmen Pilar Dolores Rosa Cristina Elena Marta Paula
Raquel Beatriz Silvia Mercedes Alicia Inés Claudia Natalia Gabriela Daniela Camila Mariana Ana Guadalupe
Ximena Valeria Fernanda Jimena Lorena Rocío Consuelo João Thiago Matheus Leonardo Vinícius Guilherme
Marcelo Paulo André Fábio Luiz Antônio Sebastião Raimundo Joaquim Manoel Gonçalo Duarte Tiago Rui Nuno
Afonso Francisca Antónia Adriana Juliana Márcia Patrícia Aline Bruna Jéssica Letícia Larissa Leonor
Matilde Carolina Pierre Michel Philippe Louis Alain Jacques Bernard Marcel Christophe François Laurent
Stéphane Julien Sébastien Olivier Thierry Frédéric Éric Pascal Didier Antoine Maxime Théo Mathis Enzo
Clément Romain Guillaume Benoît Arnaud Yves Gérard Jeanne Françoise Monique Nathalie Isabelle Sylvie
Martine Céline Sandrine Valérie Aurélie Camille Léa Manon Chloé Jade Louise Margaux Juliette Élodie Émilie
Amélie Brigitte Geneviève Hélène Mathilde Agathe Clémence Hans Klaus Jürgen Wolfgang Andreas Stefan Uwe
Dieter Günter Horst Helmut Werner Karl Heinz Bernd Rainer Manfred Gerhard Ralf Jörg Matthias Markus Tobias
Florian Sebastian Lukas Leon Finn Jonas Elias Felix Maximilian Moritz Niklas Jan Ursula Petra Sabine
Monika Gabriele Renate Karin Ingrid Helga Susanne Birgit Heike Anja Katrin Lena Lea Leonie Johanna Emilia
Greta Frieda Daan Sem Lars Bram Thijs Ruben Sven Joost Pieter Willem Hendrik Jeroen Bas Koen Wouter Sanne
Femke Lotte Anouk Fleur Marieke Annelies Giuseppe Giovanni Luigi Angelo Vincenzo Pietro Salvatore Carlo
Franco Domenico Bruno Paolo Michele Giorgio Aldo Luciano Roberto Stefano Marco Alessandro Matteo Lorenzo
Davide Simone Federico Riccardo Tommaso Edoardo Giuseppina Giovanna Lucia Carmela Caterina Francesca Chiara
Giulia Alessia Federica Elisa Paola Roberta Beatrice Aurora Ginevra Piotr Krzysztof Andrzej Tomasz Paweł
Marcin Michał Grzegorz Jakub Łukasz Mateusz Kamil Wojciech Marek Rafał Dariusz Szymon Bartosz Katarzyna
Małgorzata Agnieszka Ewa Krystyna Elżbieta Joanna Magdalena Zofia Aleksandra Zuzanna Oksana Olena Iryna
Tetiana Yulia Svitlana Andriy Oleksandr Mykola Serhiy Volodymyr Dmytro Taras Bohdan Vasyl Ivan Sergei
Sergey Dmitry Dmitri Alexei Alexey Andrei Mikhail Nikolai Vladimir Pavel Yuri Boris Igor Oleg Anatoly Viktor
Maxim Artem Kirill Anastasia Ekaterina Yekaterina Olga Tatiana Svetlana Irina Natalya Yelena Marina
Lyudmila Galina Ksenia Daria Polina Alina Vera Nadezhda Александр Сергей Дмитрий Андрей Алексей Иван
Михаил Николай Владимир Павел Евгений Максим Артём Артем Игорь Олег Юрий Виктор Борис Кирилл Роман Анна
Мария Елена Ольга Наталья Татьяна Ирина Светлана Екатерина Анастасия Юлия Марина Дарья Ксения Полина
Галина Людмила Вера Надежда Оксана Олена Ірина Тетяна Андрій Олександр Микола Сергій Володимир Дмитро
Тарас Богдан Mehmet Mustafa Ahmet Ali Hüseyin Hasan İbrahim İsmail Osman Yusuf Murat Ömer Ramazan Halil
Süleyman Abdullah Mahmut Recep Salih Kemal Emre Burak Cem Kaan Serkan Volkan Onur Barış Oğuz Tolga Uğur
Fatma Ayşe Emine Hatice Zeynep Elif Meryem Zehra Merve Özlem Esra Büşra Gizem Ebru Derya Selin Ece Melis
Defne Aylin Ayşegül Elnur Elçin Rəşad Rashad Orxan Orkhan Tural Anar Elvin Kamran Ramil Ramin Nicat Nijat
Fərid Farid Vüqar Vugar Elşən Elshan Əli Vəli Hüseyn Huseyn Məmməd Mammad Rüfət Rufat Səbinə Sabina Aynur
Günel Gunel Leyla Nigar Aysel Aysu Lalə Lala Fidan Nərmin Narmin Könül Konul Ülviyyə Ulviyya Şəbnəm
Shabnam Ləman Laman Umud Ümid Tofiq Zaur Elmar İlham Ilham Samir Səməd Samad Fuad Rauf Arzu Cəmilə
Mohammed Muhammad Mohamed Ahmed Ahmad Omar Umar Hassan Hussein Hussain Ibrahim Youssef Khalid Abdul
Mahmoud Karim Tariq Hamza Bilal Rashid Saeed Nasser Faisal Fahad Salman Ziad Walid Amir Reza Mehdi Hossein
Hamid Majid Behnam Dariush Farhad Parisa Fatima Fatemeh Aisha Ayesha Maryam Mariam Zainab Khadija Layla
Leila Noor Nour Huda Amina Samira Yasmin Yasmine Salma Rania Dina Lina Hana Zahra Narges Shirin Mina Neda
محمد أحمد علي عمر حسن حسين إبراهيم يوسف خالد فاطمة عائشة مريم زينب خديجة ليلى سارة رضا مهدی حسین زهرا
مریم Moshe Yosef Avraham Yitzhak Yaakov Noam Itai Eitan Omer Ariel Yael Noa Tamar Shira Maya Michal Rivka
דוד משה יוסף אברהם יעל נועה תמר שירה מיכל Rahul Raj Amit Sanjay Vijay Anil Sunil Rajesh Suresh Ramesh
Mahesh Deepak Arjun Rohan Vikram Aditya Karan Arun Ravi Manoj Ashok Priya Pooja Neha Anjali Sunita
Kavita Anita Rekha Deepika Shreya Aishwarya Lakshmi Divya Swati Meera Nisha Ritu राहुल अमित प्रिया पूजा
Budi Agus Dewi Siti Wahyu Eko Adi Putri Rizky Andi Rina Hendra Ayu Indah Fitri Minh Huy Hùng Tuấn Dũng
Hoa Lan Mai Linh Thảo Hương Trang Phương Quang Thành Giorgos Georgios Dimitris Nikos Kostas Ioannis
Yiannis Panagiotis Christos Vasilis Eleni Katerina Sofia Dimitra Ioanna Γιώργος Γεώργιος Δημήτρης Νίκος
Κώστας Γιάννης Ιωάννης Παναγιώτης Χρήστος Βασίλης Μαρία Ελένη Κατερίνα Σοφία Άννα Δήμητρα Ιωάννα Ion
Gheorghe Vasile Constantin Mihai Alexandru Ștefan Florin Adrian Bogdan Cristian Radu Ioana Andreea
Mihaela Alina Simona Raluca Oana Roxana Xiaoming Jun Hui Yan Ying Tao Hao Ming Jie Qiang Hiroshi Takeshi
Kenji Yuki Haruto Sota Yuto Kaito Akira Takumi Daiki Shota Yui Yuna Hina Sakura Aoi Haruka Yuko Keiko
Naoko Akiko Tomoko Minjun Seojun Jiwoo Jimin Seoyeon Jiwon Minseo Somchai Somsak Suda Siriporn Niran Malee
`);

export const SURNAMES = words(`
Smith Johnson Williams Brown Jones Garcia Miller Davis Rodriguez Martinez Hernandez Lopez Gonzalez Wilson
Anderson Taylor Moore Jackson Thompson White Harris Sanchez Clark Ramirez Lewis Robinson Walker Young Allen
King Wright Torres Nguyen Hill Flores Green Adams Nelson Baker Hall Rivera Campbell Mitchell Carter Roberts
Gomez Phillips Evans Turner Diaz Parker Cruz Edwards Collins Reyes Stewart Morris Morales Murphy Cook Rogers
Gutierrez Ortiz Morgan Cooper Peterson Bailey Reed Kelly Howard Ramos Kim Cox Ward Richardson Watson Brooks
Chavez Wood Bennett Gray Mendoza Ruiz Hughes Price Alvarez Castillo Sanders Patel Myers Long Ross Foster
Jimenez Powell Jenkins Perry Russell Sullivan Bell Coleman Butler Henderson Barnes Gonzales Fisher Vasquez
Simmons Romero Patterson Hamilton Graham Reynolds Griffin Wallace Moreno Cole Hayes Bryant Herrera Gibson
Ellis Tran Medina Aguilar Stevens Murray Ford Castro Marshall Owens Harrison Fernandez McDonald Woods
Kennedy Wells Vargas Chen Freeman Webb Tucker Guzman Burns Crawford Olson Simpson Porter Gordon Mendez
Silva Shaw Snyder Dixon Munoz Hunt Hicks Holmes Palmer Wagner Robertson Boyd Salazar Warren Mills Meyer Rice
Schmidt Garza Daniels Ferguson Nichols Stephens Soto Weaver Gardner Payne Dunn Kelley Spencer Hawkins
Pierce Vazquez Hansen Peters Santos Hart Bradley Knight Elliott Cunningham Duncan Armstrong Hudson Carroll
Riley Andrews Alvarado Delgado Berry Perkins Hoffman Johnston Matthews Pena Richards Contreras Willis
Carpenter Sandoval O'Brien O'Connor O'Neill Byrne Walsh Doyle Kavanagh Quinn Brennan Lynch Fitzgerald
Müller Mueller Schneider Fischer Weber Becker Schulz Hoffmann Schäfer Koch Bauer Richter Klein Schröder
Neumann Schwarz Zimmermann Braun Krüger Hofmann Hartmann Lange Schmitt Krause Meier Lehmann Schmid Schulze
Maier Köhler Herrmann König Mayer Huber Kaiser Fuchs Möller Weiß Jung Hahn Vogel Friedrich Keller Günther
Berger Winkler Roth Beck Lorenz Baumann Franke Albrecht Schuster Böhm Kraus Schumacher Krämer Vogt Jäger
Seidel Brandt Haas Schreiber Dietrich Ziegler Kuhn Pohl Engel Busch Bergmann Voigt Sauer Wolff Pfeiffer
Jansen Bakker Janssen Visser Smit Meijer Mulder Bos Vos Hendriks Dekker Brouwer Dijkstra Smits Bernard
Dubois Petit Durand Leroy Moreau Lefebvre Bertrand Roux Fournier Morel Girard Lefèvre Mercier Dupont
Lambert Bonnet Legrand Garnier Faure Rousseau Blanc Guerin Roussel Perrin Morin Mathieu Gauthier Dumont
Fontaine Chevalier Robin García Fernández González Rodríguez López Martínez Sánchez Pérez Gómez Jiménez
Hernández Díaz Muñoz Álvarez Alonso Gutiérrez Navarro Domínguez Vázquez Ramírez Serrano Blanco Molina
Suárez Ortega Rubio Marín Sanz Núñez Iglesias Garrido Cortés Lozano Guerrero Cano Prieto Méndez Calvo
Gallego Vidal Márquez Peña Cabrera Campos Vega Fuentes Carrasco Caballero Nieto Pascual Santana Herrero
Montero Hidalgo Giménez Ibáñez Ferrer Durán Benítez Mora Arias Carmona Crespo Pastor Sáez Velasco Moya
Soler Parra Esteban Bravo Gallardo Rojas Ferreira Pereira Oliveira Costa Rodrigues Martins Sousa Fernandes
Gonçalves Gomes Lopes Marques Alves Almeida Ribeiro Pinto Carvalho Teixeira Moreira Correia Mendes Nunes
Soares Vieira Monteiro Cardoso Rocha Neves Coelho Cunha Pires Simões Antunes Matos Fonseca Machado Araújo
Barbosa Tavares Lourenço Figueiredo Azevedo Freitas Barros Lima Rossi Russo Ferrari Esposito Bianchi Romano
Colombo Ricci Marino Greco Gallo Conti Mancini Giordano Rizzo Lombardi Moretti Barbieri Santoro Mariani
Rinaldi Caruso Ferrara Galli Martini Leone Longo Gentile Martinelli Vitale Lombardo Coppola Marchetti
Parisi Ferraro Ferri Fabbri Marini Grasso Valentini Messina Gatti Pellegrini Palumbo Sanna Farina Rizzi
Cattaneo Morelli Amato Silvestri Mazza Grassi Pellegrino Carbone Giuliani Benedetti Barone Caputo Montanari
Palmieri Bernardi Ferretti Bellini Basile Donati Piras Battaglia Sartori Neri Costantini Milani Pagano
Ruggiero Sorrentino Nowak Kowalski Wiśniewski Wójcik Kowalczyk Kamiński Lewandowski Zieliński Szymański
Woźniak Dąbrowski Kozłowski Jankowski Mazur Wojciechowski Kwiatkowski Krawczyk Kaczmarek Piotrowski
Grabowski Kowalska Nowakowska Wiśniewska Ivanov Smirnov Kuznetsov Popov Vasiliev Petrov Sokolov Mikhailov
Novikov Fedorov Morozov Volkov Alekseev Lebedev Semenov Egorov Pavlov Kozlov Stepanov Nikolaev Orlov
Andreev Makarov Nikitin Zakharov Ivanova Smirnova Kuznetsova Popova Petrova Shevchenko Kovalenko
Bondarenko Tkachenko Kravchenko Melnyk Boyko Koval Oliynyk Иванов Смирнов Кузнецов Попов Васильев Петров
Соколов Михайлов Новиков Фёдоров Федоров Морозов Волков Лебедев Козлов Иванова Смирнова Кузнецова Попова
Петрова Шевченко Коваленко Бондаренко Ткаченко Мельник Бойко Yılmaz Kaya Demir Şahin Çelik Yıldız
Yıldırım Öztürk Aydın Özdemir Arslan Doğan Kılıç Aslan Çetin Koç Kurt Özkan Şimşek Polat Korkmaz Erdoğan
Güneş Aksoy Avcı Bulut Bozkurt Məmmədov Mammadov Əliyev Aliyev Həsənov Hasanov Hüseynov Huseynov Quliyev
Guliyev İsmayılov Ismayilov Abbasov Rəhimov Rahimov Babayev Cəfərov Jafarov Nəsirov Nasirov Orucov Orujov
Kərimov Karimov Qasımov Gasimov Musayev İbrahimov Ibrahimov Səfərov Safarov Vəliyev Valiyev Rzayev
Süleymanov Suleymanov Nağıyev Nagiyev Məmmədova Mammadova Əliyeva Aliyeva Həsənova Hasanova Hüseynova
Huseynova Həsənli Hasanli Hesenli Quliyeva Popescu Ionescu Popa Dumitru Stoica Matei Ciobanu Rusu Florea
Dinu Lazăr Nguyễn Trần Pham Phạm Hoang Hoàng Huynh Huỳnh Phan Vũ Võ Dang Đặng Bui Bùi Đỗ Hồ Ngô Duong
Dương Wang Li Zhang Liu Yang Huang Zhao Wu Zhou Xu Sun Zhu Hu Guo Lin Gao Luo Zheng Liang Xie Tang Feng
Deng Cao Peng Zeng Xiao Tian Dong Pan Yuan Cai Jiang Cheng Wei Su Ding Shen Yao Zhong Jin Cui Kong Lam
Wong Chan Leung Cheung Tsang Chow Sato Suzuki Takahashi Tanaka Watanabe Ito Yamamoto Nakamura Kobayashi
Kato Yoshida Yamada Sasaki Yamaguchi Matsumoto Inoue Kimura Hayashi Shimizu Yamazaki Mori Abe Ikeda
Hashimoto Ishikawa Ogawa Nakajima Maeda Fujita Okada Goto Lee Park Choi Jung Jeong Kang Cho Yoon Jang Lim
Seo Shin Kwon Hwang Ahn Yoo Hong Kumar Singh Sharma Gupta Shah Mehta Verma Reddy Rao Iyer Nair Joshi Mishra
Agarwal Chopra Malhotra Kapoor Bose Banerjee Chatterjee Mukherjee Pillai Menon Desai Jain Khan Hussain
Rahman Chowdhury Hossain Cohen Levi Levy Mizrahi Peretz Biton Friedman Katz Shapiro Goldberg Rosenberg
Weiss Schwartz Kaplan Azoulay Dahan Papadopoulos Papadakis Georgiou Dimitriou Nikolaou Konstantinidis
Ioannou Pappas Vlachos Oikonomou Karagiannis Antoniou Haddad Khoury Hamdan Mansour Saleh Darwish Rahimi
Hosseini Mohammadi Ahmadi Karimi Moradi Rezaei Jafari Ghorbani Sadeghi Santoso Wijaya Susanto Halim
Kusuma Gunawan Hidayat Saputra Setiawan Pratama
`);

/** Given names that are also everyday words, months or places: weaker evidence alone. */
export const AMBIGUOUS_NAMES = words(`
Will May Mark Bill Grace Hope Faith Joy Rose Lily Daisy Ivy Iris Ruby Amber Holly Jordan Austin Victoria
Florence Georgia Christian Jean Frank Ray Pat Rob Sue Don Guy Max Jack Harper Mason Hunter Parker Carter
Cooper Logan Madison Chase April June August Summer Autumn Dawn Eden Angel Claude Nova Paris Sydney Grant
Ross Long Price King Young Bell Rice Hill Wood Green White Gray Brown Black Stone Rose Ford Hart Cook Lane
Ali Jung Park Kim Lee Han Song Mai Lan Hoa Jun Sun Yang Ming Long Li Wu Hu Ito Abe Mori Lam Rao Das
Nur Deniz Sultan Umud Hana Mina Dina Lina Noor Maya Noa Indah Ayu Martin Thomas Henry Arnold Lewis Simon
`);

/**
 * Capitalised words that begin or sit inside non-person sequences. A candidate
 * name containing one is almost always a place, an organisation, a product, a
 * heading or the first word of a sentence.
 */
export const NON_PERSON = words(`
The A An This That These Those Our Your My His Her Their We I It Its In On At For From To With By Of And Or
But If When While After Before Please Thanks Thank Hi Hello Hey Dear Yes No Not All Any Some Each Every
Here There Today Tomorrow Yesterday Now Then Also Just Only Very Note Notes Re Fwd Subject Regards Best
Cheers Sincerely So As Is Are Was Were Be Been Has Have Had Do Does Did Can Could Would Should 
Shall Might Must Let Get Got See Call Send Check Use Add Set Run Click Open Close Save Delete Update
Create New Old North South East West Upper Lower Central Great Big Little Saint San Santa Los Las El La Le
Mount Lake River Street Avenue Road Lane Drive Boulevard Park Square Station Airport Hotel Hospital Clinic
University College School Institute Academy Bank Group Inc Ltd LLC Corp Corporation Company Co GmbH AG SA
PLC Foundation Association Society Council Committee Department Ministry Office Agency Bureau Service
Services System Systems Solutions Technologies Technology Software Labs Lab Studio Studios Media News Times
Post Daily Journal Review Press Cloud Platform Network Networks Data Digital Global International National
Federal State City County Republic Kingdom United Union Empire Center Centre Museum Library Church Temple
Mosque Cathedral Castle Palace Tower Bridge Island Islands Beach Valley Mountain Mountains Desert Forest
Ocean Sea Gulf Bay Coast Cape Peninsula Monday Tuesday Wednesday Thursday Friday Saturday Sunday January
February March July September October November December Christmas Easter Ramadan Thanksgiving Halloween
God Lord Allah Internet Web Google Microsoft Apple Amazon Meta Facebook Twitter Instagram OpenAI Anthropic
GitHub Gitlab Linux Windows Android Python Java JavaScript TypeScript Rust Docker Kubernetes Azure Slack Zoom
Teams Excel Word PowerPoint Chrome Firefox Safari Edge ChatGPT Gemini Copilot Production Staging Development
Default Main Primary Secondary Test Testing Demo Example Sample Server Cluster Database Project Team Admin
Administrator User Users Guest Root Unknown None Null Undefined True False Untitled Customer Client Account
Order Invoice Ticket Error Warning Info Debug Total Summary Report Status Pending Approved Rejected Version
Release Build Model Machine Learning Deep Neural Artificial Intelligence Privacy Policy Terms Security
Support Sales Marketing Finance Engineering Product Design Research Legal Human Resources Operations Manager
Director President Senator Governor Mayor Minister Prime Chief Officer Doctor Professor Captain General
France Germany Spain Italy Portugal Netherlands Belgium Poland Ukraine Russia Turkey Azerbaijan Greece
Romania China Japan Korea India Pakistan Iran Iraq Israel Egypt Brazil Mexico Canada America Australia
England Britain Scotland Ireland Wales Europe Asia Africa London Berlin Madrid Rome Moscow Baku Istanbul
Ankara Tokyo Beijing Shanghai Delhi Mumbai York Angeles Francisco Chicago Boston Seattle Toronto 
Dubai Vienna Prague Warsaw Kyiv Athens Lisbon Amsterdam Brussels Munich Hamburg Milan Barcelona
English French German Spanish Italian Portuguese Dutch Polish Russian Turkish Chinese Japanese Korean
Arabic Hindi Persian Hebrew Greek Romanian Indonesian Vietnamese Thai Ukrainian Azerbaijani European
American African Asian Muslim Jewish Catholic Islamic Royal Imperial Grand First Second Third
Last Next Final Annual Monthly Weekly Quarterly Later However Meanwhile Finally Afterwards Sometimes Maybe
Perhaps Unfortunately Actually Instead Still Again Once Since Because Although Though Unless Until Whether
Where What Who Why How Which Today Ok Okay Sure Good Great
`);
