1)

select
    employee_id, department_name
    MAX(salary) as max_sal, 
    MAX(salary) - (SELECT MAX(salary) 
                   FROM Employee 
                   WHERE Salary NOT IN ( 
                                        SELECT Max(Salary) FROM Employee)) 
                AS DIFF_salary
From Employees E inner join departments  L on (E.department_id = L.department_id)
GROUP BY department_id

2)

select 100 * COUNT(*)/ (SELECT COUNT(1) from site_visitors)
select
    [date], site, num_vis

FROM
     site_visitors sv right join promotion_dates pd on (sv.promotionid = pd.promotion_id) -- only visits on promotions
     WHERE
        [date] between [start_date] and [end_date]