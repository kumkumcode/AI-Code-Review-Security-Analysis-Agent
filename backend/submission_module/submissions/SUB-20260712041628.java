import java.util.Scanner;

public class StudentGrade {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in)

        System.out.print("Enter student name: ");
        String name = sc.nextLine()

        System.out.print("Enter marks: ");
        int marks = sc.nextInt();

        if (marks >= 90 {
            System.out.println("Grade A");
        } else {
            System.out.println("Grade B")
        }

        sc.close();
    }
}